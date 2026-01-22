#ifndef ART_H 
#define ART_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct art_tree art_tree;

// Initialize a new ART tree
// Returns a pointer to the new tree or NULL if failed
art_tree *art_new(void);

// Destroy the tree.
void art_free(art_tree *t);

void *art_insert(art_tree *t, const unsigned char *key, int len, void *value);

void *art_delete(art_tree *t, const unsigned char *key, int len);

#endif