/* hashmap.h */
#include <stdbool.h>

typedef int (*comparator_t)(void *, void *);
typedef int (*hash_t)(void *);
typedef struct str_hashmap hashmap_t;
typedef struct {
    void *first;
    void *second;
} pair_t;

int string_hash(void *);
int string_comparator(void *, void *);
hashmap_t *hashmap_new_string(int size);
hashmap_t *hashmap_new(hash_t, comparator_t, int);
bool hashmap_put(hashmap_t *, void *, void *);
void *hashmap_get(hashmap_t *, void *);
void *hashmap_remove(hashmap_t *, void *);
void hashmap_dispose(hashmap_t *);
pair_t *hashmap_iterator(hashmap_t *hm);
pair_t *hashmap_next(pair_t *it);

/* hashmap.c */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct str_node {
    int hash;
    void *key;
    void *data;
    struct str_node *next;
} node_t;

struct str_hashmap {
    comparator_t compare;
    hash_t hash;
    int size;
    node_t *node[0];
};

typedef struct {
    pair_t kp;
    hashmap_t *hm;
    int index;
    node_t *next;
} iterator_t;

int string_comparator(void *a, void *b) {
    return strcmp(a, b);
}

int string_hash(void *key) {
    char *c = key;
    int32_t h = 0;
    while (*c != '\0') {
        h = 31 * h + *(c++);
    }
    return h;
}

hashmap_t *hashmap_new_string(int size) {
    return hashmap_new(string_hash, string_comparator, size);
}

hashmap_t *hashmap_new(hash_t h, comparator_t c, int size) {
    hashmap_t *hm = malloc(sizeof(hashmap_t) + sizeof(node_t *)*size);
    hm->compare = c;
    hm->hash = h;
    hm->size = size;
    int i;
    for (i = 0; i < size; i++) {
        hm->node[i] = NULL;
    }
    return hm;
}

bool hashmap_put(hashmap_t *hm, void *key, void *data) {
    int hash = hm->hash(key);
    int bucket = (unsigned int)hash % hm->size;
    node_t **n = &hm->node[bucket];
    while (*n != NULL) {
        node_t *c = *n;
        if (c->hash == hash && hm->compare(c->key, key) == 0) {
            c->data = data;
            return false;
        }
        n = &c->next;
    }
    *n = malloc(sizeof(node_t));
    node_t *mn = *n;
    mn->hash = hash;
    mn->key = key;
    mn->data = data;
    mn->next = NULL;
    return true;
}

void *hashmap_get(hashmap_t *hm, void *key) {
    int hash = hm->hash(key);
    int bucket = (unsigned int)hash % hm->size;
    node_t **n = &hm->node[bucket];
    while (*n != NULL) {
        node_t *c = *n;
        if (c->hash == hash && hm->compare(c->key, key) == 0) {
            return c->data;
        }
        n = &c->next;
    }
    return NULL;
}

void *hashmap_remove(hashmap_t *hm, void *key) {
    int hash = hm->hash(key);
    int bucket = (unsigned int)hash % hm->size;
    node_t **n = &hm->node[bucket];
    while (*n != NULL) {
        node_t *c = *n;
        if (c->hash == hash && hm->compare(c->key, key) == 0) {
            *n = c->next;
            void *data = c->data;
            free(c);
            return data;
        }
        n = &c->next;
    }
    return NULL;
}

void hashmap_dispose(hashmap_t *hm) {
    int i;
    for (i = 0; i < hm->size; i++) {
        node_t *mn = hm->node[i];
        while (mn != NULL) {
            node_t *m = mn;
            mn = m->next;
            free(m);
        }
    }
    free(hm);
}

pair_t *hashmap_iterator(hashmap_t *hm) {
    iterator_t *i = malloc(sizeof(iterator_t));
    i->kp.first = NULL;
    i->kp.second = NULL;
    i->hm = hm;
    i->index = -1;
    i->next = NULL;
    return &i->kp;
}

pair_t *hashmap_next(pair_t *it) {
    iterator_t *i = (iterator_t *)it;
    if (i->next) {
        i->kp.first = i->next->key;
        i->kp.second = i->next->data;
        i->next = i->next->next;
        return &i->kp;
    } else {
        for (i->index++; i->index < i->hm->size; i->index++) {
            node_t *mn = i->hm->node[i->index];
            if (mn != NULL) {
                i->kp.first = mn->key;
                i->kp.second = mn->data;
                i->next = mn->next;
                return &i->kp;
            }
        }
        free(i);
        return NULL;
    }
}

/* alignment.h */
#include <stddef.h>

static inline size_t alignTo(size_t val, size_t alignment) {
    return ((val - 1) / alignment + 1) * alignment;
}

static inline size_t alignDown(size_t val, size_t alignment) {
    return val / alignment * alignment;
}

/* gc.c */
#include <stdlib.h>
#include <stdio.h>

#define CLEANED_FLAG 1
#define ROOT_FLAG 2

static int pointer_comparator(void *a, void *b) {
    return a - b;
}

static int pointer_hash(void *a) {
    return (int)(size_t)a;
}

#define MIN_CUTOFF (1024*8)
/* This is a platform dependent value.
 * I don't want to seek for a perfect value for all platform,
 * but value 0 is aggressive. I generally use value 128, which
 * should be enough to cover the stack frame of the caller.*/
#define STACK_OFFSET 128

static hashmap_t *gc_heap;
static void *stackTop;
static size_t cutoff = MIN_CUTOFF;
static size_t allocated = 0;

void gc_init(void);
void gc_clean(void);
void *gc_malloc(size_t size);
void *gc_malloc_ptr(size_t size, size_t ptrsSize);
void gc_addRoot(void *ptr, size_t size);
void gc_removeRoot(void *ptr);

void gc_init(void) {
    gc_heap = hashmap_new(pointer_hash, pointer_comparator, 97);
    __asm__ __volatile__("mov %%esp, %0": "=g"(stackTop));
    stackTop += STACK_OFFSET;
}

void *gc_malloc(size_t size) {
    if (allocated > cutoff) {
        gc_clean();
    }
    size = alignTo(size, 4);
    void *ptr = malloc(size);
    memset(ptr, 0, size);
    hashmap_put(gc_heap, ptr, (void *)size);
    allocated += size;
    return ptr;
}

void *gc_malloc_ptr(size_t size, size_t ptrsSize) {
    if (allocated > cutoff) {
        gc_clean();
    }
    size = alignTo(size, 4);
    ptrsSize = alignTo(ptrsSize, 4);
    void *ptr = malloc(size);
    memset(ptr, 0, size);
    hashmap_put(gc_heap, ptr, (void *)ptrsSize);
    allocated += ptrsSize;
    return ptr;
}

void gc_addRoot(void *ptr, size_t size) {
    size = alignTo(size, 4);
    hashmap_put(gc_heap, ptr, (void *)(size | ROOT_FLAG));
}

void gc_removeRoot(void *ptr) {
    hashmap_remove(gc_heap, ptr);
}

static void gc_mark(void *base, size_t size) {
    if (size & CLEANED_FLAG) {
        return;
    }
    hashmap_put(gc_heap, base, (void *)(size | CLEANED_FLAG));
    size &= ~ROOT_FLAG;
    void **rbase = base;
    int i;
    for (i = 0; i < size / sizeof(size_t); i++) {
        void *b = rbase[i];
        size_t s = (size_t)hashmap_get(gc_heap, b);
        if (s) {
            gc_mark(b, s);
        }
    }
    return;
}

static void gc_clean_real(void *stackBottom){
    gc_addRoot(stackBottom, stackTop - stackBottom);

    size_t beforeClean = allocated;

    pair_t *p = hashmap_iterator(gc_heap);
    for (p = hashmap_next(p); p != NULL; p = hashmap_next(p)) {
        hashmap_put(gc_heap, p->first, (void *)((size_t)p->second & ~CLEANED_FLAG));
    }

    p = hashmap_iterator(gc_heap);
    for (p = hashmap_next(p); p != NULL; p = hashmap_next(p)) {
        if ((size_t)p->second & ROOT_FLAG) {
            gc_mark(p->first, (size_t)p->second);
        }
    }

    p = hashmap_iterator(gc_heap);
    for (p = hashmap_next(p); p != NULL; p = hashmap_next(p)) {
        if (!((size_t)p->second & CLEANED_FLAG)) {
            allocated -= (size_t)p->second;
            hashmap_remove(gc_heap, p->first);
            free(p->first);
        }
    }

    cutoff = allocated + 1024 > MIN_CUTOFF ? allocated + 1024 : MIN_CUTOFF;

    if(1)
        if (beforeClean != allocated)
            printf("[GC %d bytes recycled]\n", beforeClean - allocated);

    gc_removeRoot(stackBottom);
}

void gc_clean(void) {
    void *stackBottom;
    __asm__ __volatile__("mov %%esp, %0":"=a"(stackBottom)::"ebx", "ecx", "edx", "esi", "edi");
    gc_clean_real(stackBottom);
}

int main(void){
    /* Important! Make the gc know where stack starts! */
    gc_init();
    int i;
    for(i=0;i<1000;i++){
        gc_malloc(1024);
    }
    gc_clean();
    /* Please notice that since some garbage value will resides in memory or register,
     * the recycle might be conservative */
}
