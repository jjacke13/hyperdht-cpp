/* Min-heap for timers — adapted from libuv's src/heap-inl.h.
 * Binary min-heap with {left, right, parent} pointers per node.
 * Comparison via user-provided less-than function.
 */

#ifndef UV_HEAP_INL_H
#define UV_HEAP_INL_H

#include <stddef.h>

struct heap_node {
  struct heap_node* left;
  struct heap_node* right;
  struct heap_node* parent;
};

struct heap {
  struct heap_node* min;
  unsigned int nelts;
};

#define HEAP_NODE_DATA(type, field, node) \
  ((type*)((char*)(node) - offsetof(type, field)))

static inline void heap_init(struct heap* heap) {
  heap->min = NULL;
  heap->nelts = 0;
}

static inline struct heap_node* heap_min(const struct heap* heap) {
  return heap->min;
}

/* Swap two nodes in the heap. */
static inline void heap_node_swap(struct heap* heap,
                                  struct heap_node* parent,
                                  struct heap_node* child) {
  struct heap_node* sibling;
  struct heap_node t;

  t = *parent;
  *parent = *child;
  *child = t;

  parent->parent = child;
  if (child->left == child)
    child->left = parent;
  if (child->right == child)
    child->right = parent;

  if (parent->left != NULL)
    parent->left->parent = parent;
  if (parent->right != NULL)
    parent->right->parent = parent;

  if (child->left != NULL)
    child->left->parent = child;
  if (child->right != NULL)
    child->right->parent = child;

  sibling = child->parent;
  if (sibling != NULL) {
    if (sibling->left == child)
      sibling->left = parent; /* was child, now swapped */
    else
      sibling->right = parent;
  } else {
    /* child was root — parent may have taken its place incorrectly. */
  }

  /* Fix: after swap, if parent has no parent, it's the new root. */
  if (parent->parent == NULL)
    heap->min = parent;
  else if (child->parent == NULL)
    heap->min = child;
}

/* Find the position for the n-th element (1-indexed) by tracing
 * the path from root to the n-th leaf position. */
static inline struct heap_node** heap_find_pos(struct heap* heap,
                                               unsigned int n) {
  /* Walk from the root, choosing left or right at each level
   * based on the binary representation of n. */
  struct heap_node** parent_slot;
  struct heap_node* current;
  unsigned int bit;
  unsigned int shift;

  /* Find the highest set bit below n */
  for (shift = 0; (1u << (shift + 1)) <= n; shift++)
    ;

  parent_slot = &heap->min;
  current = heap->min;

  while (shift > 0) {
    shift--;
    bit = (n >> shift) & 1;
    if (current == NULL)
      return parent_slot;
    if (bit == 0)
      parent_slot = &current->left;
    else
      parent_slot = &current->right;
    current = *parent_slot;
  }

  return parent_slot;
}

static inline void heap_insert(struct heap* heap,
                               struct heap_node* newnode,
                               int (*less_than)(const struct heap_node*,
                                                const struct heap_node*)) {
  newnode->left = NULL;
  newnode->right = NULL;
  newnode->parent = NULL;

  heap->nelts++;

  if (heap->min == NULL) {
    heap->min = newnode;
    return;
  }

  /* Walk up to find the correct parent */
  {
    /* Simpler approach: insert at bottom, bubble up. */
    struct heap_node* parent_node;
    unsigned int n = heap->nelts;
    unsigned int path = 0;
    unsigned int depth = 0;
    unsigned int tmp = n;

    while (tmp > 1) {
      path = (path << 1) | (tmp & 1);
      tmp >>= 1;
      depth++;
    }

    parent_node = heap->min;
    while (depth > 1) {
      if (path & 1)
        parent_node = parent_node->right;
      else
        parent_node = parent_node->left;
      path >>= 1;
      depth--;
    }

    newnode->parent = parent_node;
    if (path & 1)
      parent_node->right = newnode;
    else
      parent_node->left = newnode;
  }

  /* Bubble up */
  while (newnode->parent != NULL &&
         less_than(newnode, newnode->parent)) {
    /* We need to swap node data, not pointers, to maintain
     * heap structure. But that's complex. Instead, use a simpler
     * approach: swap the surrounding pointers. */
    struct heap_node* p = newnode->parent;
    struct heap_node* pp = p->parent;
    struct heap_node* nl = newnode->left;
    struct heap_node* nr = newnode->right;

    /* newnode takes parent's place */
    newnode->parent = pp;
    if (pp != NULL) {
      if (pp->left == p) pp->left = newnode;
      else pp->right = newnode;
    } else {
      heap->min = newnode;
    }

    /* p becomes child of newnode */
    if (p->left == newnode) {
      newnode->left = p;
      newnode->right = p->right;
      if (p->right) p->right->parent = newnode;
    } else {
      newnode->right = p;
      newnode->left = p->left;
      if (p->left) p->left->parent = newnode;
    }

    p->parent = newnode;
    p->left = nl;
    p->right = nr;
    if (nl) nl->parent = p;
    if (nr) nr->parent = p;
  }
}

static inline void heap_remove(struct heap* heap,
                               struct heap_node* node,
                               int (*less_than)(const struct heap_node*,
                                                const struct heap_node*)) {
  if (heap->nelts == 0)
    return;

  if (heap->nelts == 1) {
    heap->min = NULL;
    heap->nelts = 0;
    return;
  }

  /* Find the last node in the heap */
  struct heap_node* last;
  {
    unsigned int n = heap->nelts;
    unsigned int path = 0;
    unsigned int depth = 0;
    unsigned int tmp = n;

    while (tmp > 1) {
      path = (path << 1) | (tmp & 1);
      tmp >>= 1;
      depth++;
    }

    last = heap->min;
    while (depth > 0) {
      if (path & 1)
        last = last->right;
      else
        last = last->left;
      path >>= 1;
      depth--;
    }
  }

  /* Detach last from its parent */
  if (last->parent) {
    if (last->parent->left == last)
      last->parent->left = NULL;
    else
      last->parent->right = NULL;
  }
  heap->nelts--;

  if (last == node) {
    if (heap->nelts == 0)
      heap->min = NULL;
    return;
  }

  /* Replace node with last */
  last->left = node->left;
  last->right = node->right;
  last->parent = node->parent;

  if (node->left) node->left->parent = last;
  if (node->right) node->right->parent = last;

  if (node->parent) {
    if (node->parent->left == node)
      node->parent->left = last;
    else
      node->parent->right = last;
  } else {
    heap->min = last;
  }

  /* Bubble up if needed */
  while (last->parent != NULL && less_than(last, last->parent)) {
    struct heap_node* p = last->parent;
    struct heap_node* pp = p->parent;
    struct heap_node* ll = last->left;
    struct heap_node* lr = last->right;

    last->parent = pp;
    if (pp) {
      if (pp->left == p) pp->left = last;
      else pp->right = last;
    } else {
      heap->min = last;
    }

    if (p->left == last) {
      last->left = p;
      last->right = p->right;
      if (p->right) p->right->parent = last;
    } else {
      last->right = p;
      last->left = p->left;
      if (p->left) p->left->parent = last;
    }

    p->parent = last;
    p->left = ll;
    p->right = lr;
    if (ll) ll->parent = p;
    if (lr) lr->parent = p;
  }

  /* Bubble down if needed */
  for (;;) {
    struct heap_node* smallest = last;
    if (last->left && less_than(last->left, smallest))
      smallest = last->left;
    if (last->right && less_than(last->right, smallest))
      smallest = last->right;
    if (smallest == last)
      break;

    /* Swap last and smallest */
    struct heap_node* child = smallest;
    struct heap_node* cp = last->parent;
    struct heap_node* cl = last->left;
    struct heap_node* cr = last->right;
    struct heap_node* ccl = child->left;
    struct heap_node* ccr = child->right;

    last->parent = child;
    child->parent = cp;
    if (cp) {
      if (cp->left == last) cp->left = child;
      else cp->right = child;
    } else {
      heap->min = child;
    }

    if (cl == child) {
      child->left = last;
      child->right = cr;
      if (cr) cr->parent = child;
    } else {
      child->right = last;
      child->left = cl;
      if (cl) cl->parent = child;
    }

    last->left = ccl;
    last->right = ccr;
    if (ccl) ccl->parent = last;
    if (ccr) ccr->parent = last;
  }
}

#endif /* UV_HEAP_INL_H */
