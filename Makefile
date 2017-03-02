CC	= gcc
CFLAGS	= -std=gnu99 -ggdb
UNAME_M := $(shell uname -m)

.PHONY: x86_64

all:
ifeq ($(UNAME_M),x86_64)
	$(MAKE) x86_64
endif

x86_64:
	$(CC) $(CFLAGS) -o inject utils.c ptrace.c elf_hook.c inject-x86_64.c -ldl
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o libsample.so -fPIC sample-library.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o libsampleupdate.so -fPIC sample-library-update.c
	$(CC) $(CFLAGS) -o sample-target -I. -L. -lsample -Wl,-rpath=. sample-target.c

libsample.so: sample-library.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o libsample.so -fPIC sample-library.c

libsample-update.so: sample-library-update.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o libsampleupdate.so -fPIC sample-library-update.c

sample-target: sample-target.c
	$(CC) $(CFLAGS) -o sample-target -I. -L. -lsample -Wl,-rpath=. sample-target.c

clean:
	rm -f libsample.so
	rm -f libsampleupdate.so
	rm -f sample-target
	rm -f inject
