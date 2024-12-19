#ifndef HYDROGEN_UTIL_LIST_H
#define HYDROGEN_UTIL_LIST_H

#include <stdbool.h>
#include <stddef.h>

typedef struct list_node {
    struct list_node *prev;
    struct list_node *next;
} list_node_t;

typedef struct {
    list_node_t *first;
    list_node_t *last;
} list_t;

#define node_to_obj(type, field, node)                                                                                 \
    ({                                                                                                                 \
        void *_n = (node);                                                                                             \
        _n ? (type *)(_n - offsetof(type, field)) : NULL;                                                              \
    })

#define list_foreach(list, type, field, var)                                                                           \
    for (type *var = node_to_obj(type, field, (list).first); var != NULL;                                              \
         var = node_to_obj(type, field, var->field.next))

bool list_is_empty(list_t *list);

void list_insert_head(list_t *list, list_node_t *value);

void list_insert_tail(list_t *list, list_node_t *value);

void list_insert_before(list_t *list, list_node_t *before, list_node_t *value);

list_node_t *list_remove_head(list_t *list);

list_node_t *list_remove_tail(list_t *list);

void list_remove(list_t *list, list_node_t *value);

void list_transfer_tail(list_t *dest, list_t *src);

void list_clear(list_t *list);

#endif // HYDROGEN_UTIL_LIST_H
