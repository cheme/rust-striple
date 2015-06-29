
#ifndef __RUST_STRIPLE_H
#define __RUST_STRIPLE_H

#include <stdlib.h>
#include <string.h>

typedef char bool;
#define true 1
#define false 0

struct striple_ptr;

struct owned_striple_ptr;

struct striple_iter;

// if not owned next is null
struct either_owned {
    struct striple_ptr * s;
    struct owned_striple_ptr * os;
};


struct striple_bytes {
    unsigned char *bytes;
    size_t length;
};

struct striple_bytes_array {
    struct striple_bytes * sb;
    size_t length;
};

struct striple_bcont {
    unsigned char *bytes;
    size_t length;
    bool ispath;
};

void dispptr(const void * it);

struct striple_iter * file_iter(const char * path);
const struct either_owned * iter_next(struct striple_iter * it);

void rust_drop(void * st);

struct striple_bytes get_id(struct striple_ptr * st);
struct striple_bytes get_enc(struct striple_ptr * st);

struct striple_bytes get_about(struct striple_ptr * st);
struct striple_bytes get_key(struct striple_ptr * st);
struct striple_bytes get_algo_key(struct striple_ptr * st);
struct striple_bytes get_sig(struct striple_ptr * st);
struct striple_bytes_array get_content_ids(struct striple_ptr * st);
struct striple_bcont get_content(struct striple_ptr * st);


void print_bytes(struct striple_bytes b) {
  for (int i = 0; i < (b.length); ++i) {
    printf("%c ", b.bytes[i]);
  }
  printf("\n");
}


// no effect??
void free_striple(struct striple_ptr * st);
// no effect??
void free_iter(struct striple_iter * iter);
// no effect??
void free_sba(struct striple_bytes_array ba);
void free_bcont(struct striple_bcont bc);

#endif
