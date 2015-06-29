gcc examples/capi/test.c -lstriple -Ltarget/debug -o test

#LD_LIBRARY_PATH=./target/debug/ valgrind ./test
LD_LIBRARY_PATH=./target/debug/ ./test

