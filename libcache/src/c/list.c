#include "list.h"
#include <stdlib.h>

void initAddrList(addr_list_t *list) {
    list->length = 0;
    list->first = 0;
    list->last = 0;
}

void freeAddrListEntries(addr_list_t *list) {
    while (list->length > 0) {
        remove_end(list);
    }
}

void deepCopyList(addr_list_t *from, addr_list_t *to) {
    for (addr_list_entry_t *e = from->first; e != 0; e = e->next) {
        insert_end(to, e->addr);
    }
}

void insert_end(addr_list_t *list, uintptr_t addr) {
    addr_list_entry_t *entry = (addr_list_entry_t*) malloc(
            sizeof(addr_list_entry_t));
    entry->addr = addr;
    entry->next = 0;
    entry->prev = list->last;
    list->last = entry;
    if (entry->prev)
        entry->prev->next = entry;
    if (!list->first)
        list->first = entry;
    list->length++;
}

void insert_front(addr_list_t *list, uintptr_t addr) {
    addr_list_entry_t *entry = (addr_list_entry_t*) malloc(
            sizeof(addr_list_entry_t));
    entry->addr = addr;
    entry->next = list->first;
    entry->prev = 0;
    list->first = entry;
    if (entry->next)
        entry->next->prev = entry;
    if (!list->last)
        list->last = entry;
    list->length++;
}

void remove_middle(addr_list_t *list, addr_list_entry_t *e) {
    if (!e->prev)
        list->first = e->next;
    else
        e->prev->next = e->next;

    if (!e->next)
        list->last = e->prev;
    else
        e->next->prev = e->prev;
    free(e);
    list->length--;
}

void remove_end(addr_list_t *list) {
    if (list->last)
        remove_middle(list, list->last);
}

uintptr_t pick_end(addr_list_t *list) {
    uintptr_t chosenElem;
    if (list->length) {
        chosenElem = list->last->addr;
        return chosenElem;
    } else {
        return 0;
    }

}

uint64_t contains(addr_list_t *list, uintptr_t addr) {
    uint64_t found = 0;
    if (!list->length)
        return 0;
    foreach(e, list)
    {
        if (e->addr == addr) {
            found = 1;
        }
    }
    return found;
}


addr_list_entry_t* find_by_address_member(addr_list_t *list, uintptr_t addr) {
    addr_list_entry_t *return_value = 0;

    if (list->length > 0) {
        for (addr_list_entry_t *e = list->first; e != 0; e = e->next) {
            if (e->addr == addr) {
                return_value = e;
                break;
            }
        }
    }

    return return_value;
}
