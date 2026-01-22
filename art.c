#include "art.h"

typedef struct art_tree art_tree;

typedef enum {
    NODE4, NODE16, NODE48, NODE256
} node_type_t;

typedef struct {
    uint8_t type;           // node_type_t
    uint8_t num_children;
    
    uint32_t partial_len;
    unsigned char partial[MAX_PREFIX_LEN];
} art_node;

struct art_tree {
    art_node *root;
    ssize_t size;
};

typedef struct {
    art_node n;
    unsigned char keys[4];
    void *children[4];
} Node4;

typedef struct {
    art_node n;
    unsigned char keys[16];
    void *children[16];
} Node16;

typedef struct {
    art_node n;
    unsigned char child_index[256];
    void *children[48];
} Node48;

typedef struct {
    art_node n;
    void *children[256];
} Node256;


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
