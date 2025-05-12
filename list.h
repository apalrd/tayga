/* Linux-style linked list implementation */

#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h> /* for offsetof() macro */

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

/* Declare an empty list */
#define LIST_HEAD(x) struct list_head x = { &x, &x }

/* Initialize an empty list (required for all malloc'd list_heads) */
static inline void INIT_LIST_HEAD(struct list_head *x)
{
	x->next = x;
	x->prev = x;
}

/* Remove an entry from its current list (if any) and insert it into the
 * beginning of the given list */
static inline void list_add(struct list_head *x, struct list_head *head)
{
	x->next->prev = x->prev;
	x->prev->next = x->next;
	x->next = head->next;
	x->prev = head;
	head->next = x;
	x->next->prev = x;
}

/* Remove an entry from its current list (if any) and insert it into the
 * end of the given list */
static inline void list_add_tail(struct list_head *x, struct list_head *head)
{
	x->next->prev = x->prev;
	x->prev->next = x->next;
	x->prev = head->prev;
	x->next = head;
	head->prev = x;
	x->prev->next = x;
}

/* Remove an entry from its current list and reinitialize it */
static inline void list_del(struct list_head *x)
{
	x->next->prev = x->prev;
	x->prev->next = x->next;
	x->next = x;
	x->prev = x;
}

#define list_del_init list_del
#define list_move list_add
#define list_move_tail list_add_tail

/* Test if list is empty (contains no other entries) */
static inline int list_empty(const struct list_head *x)
{
	return x->next == x;
}

/* Get a pointer to the object containing x, which is of type "type" and 
 * embeds x as a field called "field" */
#define list_entry(x, type, field) ({ \
		const typeof( ((type *)0)->field ) *__mptr = (x); \
		(type *)( (char *)__mptr - offsetof(type, field) );})

/* Iterate over all items in the list */
#define list_for_each(x, head) \
	for (x = (head)->next; x != (head); x = x->next)

/* Iterate over all items in the list, possibly deleting some */
#define list_for_each_safe(x, n, head) \
	for (x = (head)->next, n = x->next; x != (head); x = n, n = x->next)

#endif /* __LIST_H__ */
