#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>

#include "utils.h"
#include "ptrace.h"
#include "elf_hook.h"
#include "list.h"

char *command = NULL, *command_arg = NULL;
char *orig_libname = NULL, *new_libname = NULL;
char *proc_name = NULL;
pid_t target = 0;

struct symstr_list symstr_l;

static int parse_args(int argc, char ** argv)
{
	if (argc < 4) {
		usage(argv[0]);
		return -1;
	}

	command = argv[1];
	command_arg = argv[2];
	orig_libname = argv[3];
	new_libname = argv[4];

	if (!strcmp(command, "-n")) {
		proc_name = command_arg;
		target = find_proc_by_name(proc_name);
		if (target == -1) {
			printf("process %s is not running now\n", proc_name);
			return -1;
		}

		printf("targeting process \"%s\" with pid %d\n",
				proc_name, target);
	} else if (!strcmp(command, "-p")) {
		target = atoi(command_arg);
		printf("targeting process with pid %d\n", target);
	} else {
		usage(argv[0]);
		return -1;
	}


}

int main(int argc, char **argv)
{
	int error = 0;

	INIT_LIST_HEAD(&symstr_l.list);

	if (!parse_args(argc, argv))
		return -1;

	error = inject_shared_library(target, new_libname);
	if(error < 0)
		return error;
	
	struct symstr_list *tmp;
	printf("symbol need to be replaced:\n");
	if (parse_symbol_list(target, &symstr_l.list, orig_libname) < 0)
		return -1;

	list_for_each_entry(tmp, &symstr_l.list, list){
		printf("%s\n", tmp->string);
		if (elf_hook(target, tmp->string, new_libname, orig_libname) < 0)
			error = -1;
	}
		
	return error;
}
