#include "util/time.h"
#include "asm/cpuid.h"
#include "asm/irq.h"
#include "asm/msr.h"
#include "compiler.h"
#include "cpu/cpu.h"
#include "cpu/idt.h"
#include "cpu/irqvec.h"
#include "cpu/lapic.h"
#include "drv/hpet.h"
#include "limine.h"
#include "sched/sched.h"
#include "util/panic.h"
#include "util/print.h"
#include <limits.h>
#include <stdint.h>

uint64_t tsc_freq;
uint64_t boot_tsc;
timeconv_t tsc2ns_conv;
timeconv_t ns2tsc_conv;

static int64_t boot_timestamp;
static uint64_t lapic_freq;
static timeconv_t tsc2lapic_conv;

#define CALIBRATE_MS 500
#define CALIBRATE_FS (CALIBRATE_MS * 1000000000000)

typedef struct {
    uint64_t tsc;
    uint64_t apic;
    uint64_t hpet;
} timer_data_t;

__attribute__((noinline)) static void read_timer_data(timer_data_t *out) {
    out->tsc = read_time();
    out->apic = lapic_timcal_read();
    out->hpet = read_hpet();
}

static uint64_t get_elapsed_hpet(timer_data_t *from, timer_data_t *to) {
    uint64_t end = to->hpet;
    if (end < from->hpet) end += 0x100000000;
    return end - from->hpet;
}

static uint64_t div128(__uint128_t *dividend, uint64_t divisor) {
    uint64_t low = *dividend;
    uint64_t high = *dividend >> 64;
    uint64_t rem;

    asm("divq %[divisor]" : "=d"(rem), "=a"(high) : "0"(0ul), "1"(high), [divisor] "rm"(divisor));
    asm("divq %[divisor]" : "=d"(rem), "=a"(low) : "0"(rem), "1"(low), [divisor] "rm"(divisor));

    *dividend = low | ((__uint128_t)high << 64);
    return rem;
}

static uint64_t get_frequency(uint64_t ticks, uint64_t elapsed) {
    __uint128_t temp = (__uint128_t)1000000000000000 * ticks + (elapsed / 2);
    div128(&temp, elapsed);
    return temp;
}

static void calibrate_tsc(void) {
    unsigned eax, ebx, ecx, edx;

    if (try_cpuid(0x15, &eax, &ebx, &ecx, &edx)) {
        if (ebx != 0 && ecx != 0) {
            tsc_freq = ((uint64_t)ecx * ebx + (eax / 2)) / eax;
            lapic_freq = ecx;
            return;
        }
    }

    uint64_t hpet_ticks = (CALIBRATE_FS + (hpet_period_fs / 2)) / hpet_period_fs;
    if (hpet_ticks < 1000000) panic("time: calibration period is too short to be measured accurately");

    irq_state_t state = save_disable_irq();

    timer_data_t start, end;
    lapic_timcal_start();
    read_timer_data(&start);

    do {
        read_timer_data(&end);
    } while (get_elapsed_hpet(&start, &end) < hpet_ticks);

    restore_irq(state);

    uint64_t elapsed = get_elapsed_hpet(&start, &end) * hpet_period_fs;
    tsc_freq = get_frequency(end.tsc - start.tsc, elapsed);
    lapic_freq = get_frequency(end.apic - start.apic, elapsed);
}

static void init_tsc(void) {
    if (!tsc_supported) panic("tsc not supported");

    if (running_in_hypervisor) {
        unsigned eax, ebx, ecx, edx;
        cpuid(0x40000000, &eax, &ebx, &ecx, &edx);

        if (eax >= 0x40000010) {
            cpuid(0x40000010, &eax, &ebx, &ecx, &edx);

            if (eax != 0 && ebx != 0) {
                tsc_freq = (uint64_t)eax * 1000;
                lapic_freq = (uint64_t)ebx * 1000;
            }
        }
    }

    if (!tsc_invariant) {
        printk("time: warn: tsc not reported as invariant, timing may be unreliable\n");
    }

    if (tsc_freq == 0) calibrate_tsc();
    printk("time: tsc is %U.%6U MHz\n", tsc_freq / 1000000, tsc_freq % 1000000);

    tsc2ns_conv = timeconv_create(tsc_freq, 1000000000);
    ns2tsc_conv = timeconv_create(1000000000, tsc_freq);
    tsc2lapic_conv = timeconv_create(tsc_freq, lapic_freq);
}

static timer_event_t *timer_events;
static timer_event_t *next_timer_event;

static void reprogram_timer(void) {
    if (next_timer_event != NULL) {
        if (tsc_deadline_supported) {
            wrmsr(MSR_TSC_DEADLINE, next_timer_event->timestamp + boot_tsc);
        } else {
            uint64_t cur = read_time();
            uint64_t ticks;

            if (cur < next_timer_event->timestamp) {
                ticks = timeconv_apply(tsc2lapic_conv, next_timer_event->timestamp - cur);
                if (ticks == 0) ticks = 1;
                else if (ticks > UINT32_MAX) ticks = UINT32_MAX;
            } else {
                ticks = 1;
            }

            lapic_arm_timer(ticks);
        }
    }
}

static void handle_timer_irq(UNUSED idt_frame_t *frame) {
    timer_event_t *trig_events = NULL;
    timer_event_t *last_trig_event = NULL;

    for (;;) {
        timer_event_t *event = next_timer_event;
        if (event == NULL) break;
        if (read_time() < event->timestamp) break;

        // `event` is the earliest in the tree, so `event->left` is `NULL`
        // if there are other events at the same point in time, they will be in `event->right`
        // otherwise, the next event is `event->parent`

        if (event->right) {
            next_timer_event = event->right;

            if (event->parent) {
                event->parent->left = event->right;
            } else {
                timer_events = event->right;
            }

            event->right->parent = event->parent;
        } else if (event->parent) {
            next_timer_event = event->parent;
            event->parent->left = NULL;
        } else {
            next_timer_event = NULL;
            timer_events = NULL;
        }

        while (next_timer_event != NULL && next_timer_event->left != NULL) {
            next_timer_event = next_timer_event->left;
        }

        event->queued = false;

        event->right = NULL;
        if (trig_events) last_trig_event->right = event;
        else trig_events = event;
        last_trig_event = event;
    }

    reprogram_timer();

    disable_preempt();

    while (trig_events != NULL) {
        timer_event_t *next = trig_events->right;
        trig_events->handler(trig_events);
        trig_events = next;
    }

    lapic_eoi();
    enable_preempt();
}

void init_time(void) {
    static LIMINE_REQ struct limine_boot_time_request btime_req = {.id = LIMINE_BOOT_TIME_REQUEST};

    if (btime_req.response) {
        boot_timestamp = btime_req.response->boot_time * 1000000000;
    }

    init_tsc();
    idt_install(IRQ_TIMER, handle_timer_irq);

    if (tsc_deadline_supported) {
        printk("time: using tsc deadline for events\n");
        lapic_setup_timer(TIMER_TSC_DEADLINE);
    } else {
        printk("time: using lapic oneshot for events\n");
        lapic_setup_timer(TIMER_ONESHOT);
    }
}

void queue_event(timer_event_t *event) {
    irq_state_t state = save_disable_irq();

    timer_event_t *parent = NULL;
    timer_event_t *cur = timer_events;

    while (cur != NULL) {
        parent = cur;
        cur = event->timestamp < cur->timestamp ? cur->left : cur->right;
    }

    event->parent = parent;
    event->left = NULL;
    event->right = NULL;
    event->queued = true;

    if (parent != NULL) {
        if (event->timestamp < parent->timestamp) parent->left = event;
        else parent->right = event;

        if (event->timestamp < next_timer_event->timestamp) {
            next_timer_event = event;
            reprogram_timer();
        }
    } else {
        timer_events = event;
        next_timer_event = event;
        reprogram_timer();
    }

    restore_irq(state);
}

void cancel_event(timer_event_t *event) {
    irq_state_t state = save_disable_irq();

    if (event->queued) {
        // Remove it from the tree
        timer_event_t *replacement = event->left ? event->left : event->right;
        if (replacement != NULL) replacement->parent = event->parent;

        if (event->parent != NULL) {
            if (event->timestamp < event->parent->timestamp) {
                event->parent->left = replacement;
            } else {
                event->parent->right = replacement;
            }
        } else {
            timer_events = replacement;
        }

        // Make sure next_event is still valid
        if (event == next_timer_event) {
            next_timer_event = event->right ? event->right : event->parent;

            while (next_timer_event != NULL && next_timer_event->left != NULL) {
                next_timer_event = next_timer_event->left;
            }
        }

        event->queued = false;
    }

    restore_irq(state);
}

timeconv_t timeconv_create(uint64_t src_freq, uint64_t dst_freq) {
    /*
     * Time conversion is `T1 = (T1 * f1) / f0` (T0 = src value, f0 = src freq, T1 = dst value, f1 = dst freq).
     * However, that formula can overflow pretty quickly if the source frequency is high, making it unusable.
     * A workaround for this is using 128-bit integers for the intermediate value, but 128-bit division is either slow
     * or impossible depending on the platform. 128-bit multiplication is fine, though, and the equation can be
     * rearranged to not include 128-bit division:
     * 1. `T1 = (T1 * f1) / f0`
     * 2. `T1 = (T1 * f1 * 2^p) / (f0 * 2^p)`
     * 3. `T1 = (T1 * ((f1 * 2^p) / f0)) / 2^p`
     * Note that `((f1 * 2^p) / f0)` is a constant that can be calculated ahead of time, and the last division
     * is by a power of two and can thus be replaced with a right shift. This function calculates both `p` and
     * that constant.
     */

    // Find the highest value of `p` that doesn't make the multiplier overflow (`((f1 * 2^p) / f0) < 2^64`)

    // the highest value of `p` where the intermediate uint128_t can still be calculated
    unsigned max_p_intermediate = __builtin_clzl(dst_freq) + (128 - (sizeof(unsigned long) * CHAR_BIT));

    unsigned p;
    uint64_t multiplier;

    for (p = 0; p <= max_p_intermediate; p++) {
        __uint128_t cur_mult = (__uint128_t)dst_freq << p;
        div128(&cur_mult, src_freq);
        if (cur_mult > UINT64_MAX) break;
        multiplier = cur_mult;
    }

    p -= 1;

    return (timeconv_t){
            .multiplier = multiplier,
            .shift = p,
    };
}

int64_t get_timestamp(void) {
    return __atomic_load_n(&boot_timestamp, __ATOMIC_ACQUIRE) + timeconv_apply(tsc2ns_conv, read_time());
}

void set_timestamp(int64_t time) {
    __atomic_store_n(&boot_timestamp, time - timeconv_apply(tsc2ns_conv, read_time()), __ATOMIC_RELEASE);
}
