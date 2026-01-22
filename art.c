#include "art.h"
#include <stdlib.h>

typedef struct art_tree art_tree;

typedef enum {
    NODE4, NODE16, NODE48, NODE256, LEAF
} node_type_t;

typedef struct {
    uint8_t type;           // node_type_t
    uint8_t num_children;
    uint32_t partial_len;
    unsigned char partial[MAX_PREFIX_LEN];
} art_node;

typedef struct {
    uint8_t type;
    uint32_t len;
    void *value;
    unsigned char key[];
} art_leaf;

struct art_tree {
    void *root;
    uint64_t size;
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
art_tree *art_new(void) {
    art_tree *T = (art_tree*)malloc(sizeof(art_tree));
    if (!T) return NULL;
    T->root = NULL;
    T->size = 0;
    return T;
}

void free_node(art_node *tree_node) {
    if (!tree_node) return;
    // TODO: free all smaller node
    free(tree_node);
}

// Destroy the tree.
void art_free(art_tree *T) {
    if (!T) return;
    free_node(T->root);
    free(T);
}

bool art_empty(art_tree *T) {
    assert(T != NULL);
    return T->root == NULL;
}

static art_leaf* make_leaf(const unsigned char *key, int len, void *value) {
    art_leaf *l = calloc(1, sizeof(art_leaf) + len);
    if (!l) {
        perror("Malloc failed");
        exit(EXIT_FAILURE);
    }
    l->type = LEAF;
    l->value = value;
    l->len = len;
    memcpy(l->key, key, len);

    return l;
}

node_type_t get_type(void *node) {
    return ((art_node*)node)->type;
}

static int check_prefix(
    const unsigned char *k1, 
    int len1, const unsigned char *k2, 
    int len2, int depth
) 
{
    int max_cmp = (len1 < len2) ? len1 : len2;
    int idx = 0;
    for (; idx + depth < max_cmp; idx++) {
        if (k1[idx + depth] != k2[idx + depth]) {
            return idx;
        }
    }
    return idx;
}

// Returns NULL if create a new node,
// Returns the *old value if modify a existing node
static void *recursive_insert(
    art_node *n,
    art_node **ref,
    const unsigned char *key,
    int len,
    void *value,
    int depth,
    int *replace_flag
) 
{
    // Base case: the tree is empty
    // - Just create a leaf
    if (n == NULL) {
        art_leaf *l = make_leaf(key, len, value);
        *ref = (void*)l;
        return NULL;
    }

    // Case 1: found a leaf and the key matched exactly
    if (get_type(n) == LEAF) {
        art_leaf *l = (art_leaf*)n;

        // Case 1.a: key matched, update the value
        if (l->len == len && memcmp(l->key, key, len) == 0) {
            void *old_value = l->value;
            l->value = value;
            *replace_flag = 1;
            return old_value;
        }

        // Case 1.b: key is different, branch 
        int prefix = check_prefix(l->key, l->len, key, len, depth);

        // Setup the Node metadata
        Node4 *new_node = calloc(1, sizeof *new_node);
        new_node->n.type = NODE4;
        new_node->n.num_children = 2;
        new_node->n.partial_len = prefix;

        int partial_copy_len = (prefix < MAX_PREFIX_LEN) ? prefix : MAX_PREFIX_LEN;
        memcpy(new_node->n.partial, key + depth, partial_copy_len);

        // Find the split character
        int split_idx = depth + prefix;
        unsigned char char_old = l->key[split_idx];
        unsigned char char_new = key[split_idx];

        // Check for which one is at index 0 and 1
        int idx_old = (char_old < char_new) ? 0 : 1;
        int idx_new = (idx_old == 0) ? 1 : 0;

        art_leaf *l2 = make_leaf(key, len, value);

        new_node->children[idx_old] = l;
        new_node->children[idx_new] = l2;

        new_node->keys[idx_old] = char_old;
        new_node->keys[idx_new] = char_new;
        
        *ref = (void*)new_node;

        return NULL;
    }
    

    return NULL;
}

// Insert a key-value pair
// Key: binary string
// Value: pointer to the data you want to store
// Returns: NULL if inserted new, or old values if its a update
void *art_insert(art_tree *T, const unsigned char *key, int len, void *value) {
    // This flag sets to 1 when we modify a existing node
    int replace_flag = 0;
    
    void *old_val = recursive_insert(
        T->root, 
        (art_node **)&T->root, 
        key, 
        len, 
        value, 
        0, 
        &replace_flag
    );

    if (replace_flag == 0) {
        T->size++;
    }

    return old_val;
}

// Delete a key
// Returns: the pointer to the deleted item (you have ownership to free it)
// or NULL if key doesn't exist
void *art_delete(art_tree *t, const unsigned char *key, int len);
