#include "util/list.h"

bool list_is_empty(list_t *list) {
    return list->first == NULL;
}

void list_insert_head(list_t *list, list_node_t *value) {
    value->prev = NULL;
    value->next = list->first;

    if (value->next) value->next->prev = value;
    else list->last = value;

    list->first = value;
}

void list_insert_tail(list_t *list, list_node_t *value) {
    value->prev = list->last;
    value->next = NULL;

    if (value->prev) value->prev->next = value;
    else list->first = value;

    list->last = value;
}

void list_insert_before(list_t *list, list_node_t *before, list_node_t *value) {
    value->prev = before ? before->prev : list->last;
    value->next = before;

    if (value->prev) value->prev->next = value;
    else list->first = value;

    if (before) before->prev = value;
    else list->last = value;
}

list_node_t *list_remove_head(list_t *list) {
    list_node_t *node = list->first;

    if (node) {
        list->first = node->next;

        if (list->first) list->first->prev = NULL;
        else list->last = NULL;
    }

    return node;
}

list_node_t *list_remove_tail(list_t *list) {
    list_node_t *node = list->last;

    if (node) {
        list->last = node->prev;

        if (list->last) list->last->next = NULL;
        else list->first = NULL;
    }

    return node;
}

void list_remove(list_t *list, list_node_t *value) {
    if (value->prev) value->prev->next = value->next;
    else list->first = value->next;

    if (value->next) value->next->prev = value->prev;
    else list->last = value->prev;
}

void list_transfer_tail(list_t *dest, list_t *src) {
    if (src->first == NULL) return;

    if (dest->last != NULL) {
        src->first->prev = dest->last;
        dest->last->next = src->first;
        dest->last = src->last;
    } else {
        dest->first = src->first;
        dest->last = src->last;
    }

    src->first = NULL;
    src->last = NULL;
}

void list_clear(list_t *list) {
    list->first = NULL;
    list->last = NULL;
}
