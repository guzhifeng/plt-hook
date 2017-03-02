#include <stdio.h>
#include "libsample.h"

/*
 * libsample()
 *
 * libsample() is a replication function of libsample().
 *
 */
int libsample(int a, int b, int c)
{
	printf("call the multiplication: %d\n", a * b * c);
	return a * b * c;
}
