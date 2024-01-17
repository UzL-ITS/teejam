#ifndef LIST_H__
#define LIST_H__

#include <stdint.h>

/*
 * Defines an entry of an address list.
 * Every entry contains a pointer to the previous and to 
 * the next element.
 * As this is a list of addresses, every entry also contains an address. 
 */
typedef struct addr_list_entry_s {
    struct addr_list_entry_s *next;
    struct addr_list_entry_s *prev;
    uintptr_t addr;
} addr_list_entry_t;

/*
 * Defines a list of addresses with a first/ last element
 * and the length.
 */
typedef struct {
    addr_list_entry_t *first;
    addr_list_entry_t *last;
    int length;
} addr_list_t;

/*
 * Receives an address list and initializes the first/ last element
 * and the length.
 */
void initAddrList(addr_list_t *list);

/* Removes all elements from an address list and frees them */
void freeAddrListEntries(addr_list_t *list);

/* Creates a deep copy of an address list */
void deepCopyList(addr_list_t *from, addr_list_t *to);

/*
 * Receives an address list and an address that has to be inserted at
 * the end of the list. The pointers and the length get updated.
 */
void insert_end(addr_list_t *list, uintptr_t addr);

/*
 * Receives an address list and an address that has to be inserted
 * at the beginning of the list. The pointers and the length get updated.
 */
void insert_front(addr_list_t *list, uintptr_t addr);

/*
 * Receives an address list and an element that shall be deleted.
 */
void remove_middle(addr_list_t *list, addr_list_entry_t *e);

/*
 * Receives an address list whose last element shall be deleted.
 */
void remove_end(addr_list_t *list);

/*
 * Finds an entry base on its address
 */
addr_list_entry_t* find_by_address_member(addr_list_t *list, uintptr_t addr);

/*
 * Receives an address list and returns the last element of it if the list is
 * not empty.
 */
uintptr_t pick_end(addr_list_t *list);

/*
 * Receives an address list and an address that has to be checked.
 * Returns whether the address was found (1) in the list or not (0).
 */
uint64_t contains(addr_list_t *list, uintptr_t addr); // derzeit nicht genutzt

/*
 * Abbreviation for iterating over a list
 */

#define foreach(e, list) for (addr_list_entry_t *e = list->first; e != 0; e = e->next)

/*
 * Abbreviation for iterating over a list backwards
 */

#define foreachReverse(e, list) for (addr_list_entry_t *e = list->last; e != 0; e = e->prev)

#endif
