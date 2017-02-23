#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "libsample.h"

/*
 * sleepfunc()
 *
 * The only purpose of this function is to output the message "hello"
 * once a second to provide a more concrete idea of when the sample library
 * gets injected.
 *
 */

void sleepfunc(void)
{
	struct timespec *sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 1;
	sleeptime->tv_nsec = 0;

	while (1) {
		printf("result = %d\n", libsample(1, 2, 4));
		nanosleep(sleeptime, NULL);
	}

	free(sleeptime);
}

/*
 * main()
 *
 * Call sleepfunc(), which loops forever.
 *
 */

int main(void)
{
	sleepfunc();
	return 0;
}
