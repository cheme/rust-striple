#include <stdio.h>

#include "rust_striple.h"

int main(int argc, char *argv[]) {
    struct striple_iter * iter;
    struct striple_ptr * st;
    struct owned_striple_ptr * from = NULL;
    void * tmppt;
    struct striple_bytes id;
    struct striple_bytes enc;
    struct striple_bytes about;
    struct striple_bytes key;
    struct striple_bytes algo_key;
    struct striple_bytes sig;
    struct striple_bytes_array ctids;
    struct striple_bcont bcont;
    struct striple_bytes tmpbytes;
    int i = 0;

    const struct either_owned * eith_st;
//    struct either_owned *x = malloc(sizeof *x); 
    printf("Hello World !\n");

    iter = file_iter("./baseperm.data");
    if (iter == NULL) {
      printf("Error on opening of striple file\n");
    } else {
      printf("iter ptr val : %p \n", iter);
      dispptr(iter);
//      dispptr(x);
      eith_st = iter_next(iter);
      eith_st = iter_next(iter);
      printf("eith_it : %p \n", eith_st);
      if (eith_st != NULL) {
        if (eith_st->s != NULL) {
          printf("first strip is not owned: %p \n", eith_st->s);
          st = eith_st->s;
        } else {
          printf("first strip is owned: %p \n", eith_st->os);
          st = (struct striple_ptr *) eith_st->os;
          from = (struct owned_striple_ptr *)eith_st->os;
        }
      } else {
        printf("empty iter");
      }
    }

    if (st != NULL) {
      // call st primitives
      printf("bef\n ");
      id = get_id(st);
      printf("aft\n ");

      printf("id: ");
      print_bytes(id);
      
      enc = get_enc(st);
      printf("enc: ");
      print_bytes(enc);

      about = get_about(st);
      printf("about: ");
      print_bytes(about);
 
      key = get_key(st);
      printf("key: ");
      print_bytes(key);
 
      algo_key = get_algo_key(st);
      printf("algo_key: ");
      print_bytes(algo_key);

      sig = get_sig(st);
      printf("sig: ");
      print_bytes(sig);

      ctids = get_content_ids(st);
      printf("content_ids: ");
      i = ctids.length;
      for (int j = 0; j < i; ++j) {
        printf("  - %d : ", j);
        print_bytes(ctids.sb[i]);
      }

      bcont = get_content(st);
      printf("content: \n");
      printf(" - val : ");
      tmpbytes = (struct striple_bytes) { bcont.bytes, bcont.length};
      print_bytes(tmpbytes);
      printf(" - isfile : %d\n", bcont.ispath);
      

    }

    // TODO create new one with st values (and possibly from ptr)
    return 0;
}

