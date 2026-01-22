#ifndef ART_H 
#define ART_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>

#define MAX_PREFIX_LEN 10

typedef struct art_tree art_tree;

// Initialize a new ART tree
// Returns a pointer to the new tree or NULL if failed
art_tree *art_new(void);

// Destroy the tree.
void art_free(art_tree *t);

// Insert a key-value pair
// Key: binary string
// Value: pointer to the data you want to store
// Returns: NULL if inserted new, or old values if its a update
void *art_insert(art_tree *t, const unsigned char *key, int len, void *value);

// Delete a key
// Returns: the pointer to the deleted item (you have ownership to free it)
// or NULL if key doesn't exist
void *art_delete(art_tree *t, const unsigned char *key, int len);

#endif