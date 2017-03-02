#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>

#include "utils.h"
#include "ptrace.h"

int main(int argc, char **argv)
{
	char *command, *commandArg;
	char *libname;
	char *processName;
	char *origLibName;
	pid_t target_pid = 0;
	int error = 0;

	if (argc < 5) {
		usage(argv[0]);
		return 1;
	}

	command = argv[1];
	commandArg = argv[2];
	libname = argv[3];
	origLibName = argv[4];

	if (!strcmp(command, "-n")) {
		processName = commandArg;
		target_pid = findProcessByName(processName);
		if (target_pid == -1) {
			printf("process \"%s\" is not running right now\n",
					processName);
			return 1;
		}

		printf("targeting process \"%s\" with pid %d\n",
				processName, target_pid);
	} else if (!strcmp(command, "-p")) {
		target_pid = atoi(commandArg);
		printf("targeting process with pid %d\n", target_pid);
	} else {
		usage(argv[0]);
		return 1;
	}

	error = inject_shared_library(target_pid, libname, origLibName);
	if(error)
		return error;
}
