#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include "elf_hook.h"

/*
 * libsampleupdate()
 *
 * libsampleupdate() is a replication function of libsample().
 *
 */
int libsampleupdate(int a, int b, int c)
{
	printf("call the multiplication: %d\n", a * b * c);
	return a * b * c;
}

/*
 * libsamplehook()
 *
 * This function is automatically called when the libsampleupdate.so is
 * injected into target process.
 *
 */

__attribute__((constructor))
void libsamplehook(void)
{
	void *original = NULL;
	ssize_t len;
	char *elfPath;

	elfPath = malloc(PATH_MAX * sizeof(char));
	if (elfPath == NULL)
		fprintf(stderr, "malloc failed \"%d\" !\n", errno);

	len = readlink("/proc/self/exe", elfPath, PATH_MAX - 1);
	if (len == -1)
		fprintf(stderr, "readlink failed \"%d\" !\n", errno);

	elfPath[len] = '\0';

	original = elf_hook(elfPath, "libsample", libsampleupdate);

	if (original == NULL)
		fprintf(stderr, "Redirection failed!\n");

	free(elfPath);
}
