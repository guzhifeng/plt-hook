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
	char *libname, *libPath;
	char *processName;
	char *origLibName;
	pid_t mypid = 0, target = 0;
	int libPathLength;
	long mylibcaddr, targetLibcAddr;
	long mallocAddr, freeAddr, dlopenAddr;
	long mallocOffset, freeOffset, dlopenOffset;
	long targetMallocAddr, targetFreeAddr, targetDlopenAddr;
	struct user_regs_struct oldregs, regs;
	struct user_regs_struct target_regs;
	long addr;
	size_t target_snippet_size;
	//intptr_t target_snippet_ret;
	//char *backup, *newcode;
	unsigned long long targetBuf;
	unsigned long long libAddr;
	char *backup;
	int error = 0;

	if (argc < 5) {
		usage(argv[0]);
		return 1;
	}

	command = argv[1];
	commandArg = argv[2];
	libname = argv[3];
	origLibName = argv[4];
	libPath = realpath(libname, NULL);

	if (!libPath) {
		fprintf(stderr, "can't find file \"%s\"\n", libname);
		return 1;
	}

	if (!strcmp(command, "-n")) {
		processName = commandArg;
		target = findProcessByName(processName);
		if (target == -1) {
			printf("process \"%s\" is not running right now\n",
					processName);
			return 1;
		}

		printf("targeting process \"%s\" with pid %d\n",
				processName, target);
	} else if (!strcmp(command, "-p")) {
		target = atoi(commandArg);
		printf("targeting process with pid %d\n", target);
	} else {
		usage(argv[0]);
		return 1;
	}

	libPathLength = strlen(libPath) + 1;

	mypid = getpid();
	mylibcaddr = getSharedLibAddr(mypid, "libc-");
	targetLibcAddr = getSharedLibAddr(target, "libc-");

	/* find the addresses of the syscalls that we'd like to use inside the
	 * target, as loaded inside THIS process (i.e. NOT the target process)
	 * use the base address of libc to calculate offsets for the syscalls
	 * we want to use
	 */

	mallocAddr = getFunctionAddress("malloc");
	freeAddr = getFunctionAddress("free");
	dlopenAddr = getFunctionAddress("__libc_dlopen_mode");

	mallocOffset = mallocAddr - mylibcaddr;
	freeOffset = freeAddr - mylibcaddr;
	dlopenOffset = dlopenAddr - mylibcaddr;

	/* get the target process' libc function address */
	targetMallocAddr = targetLibcAddr + mallocOffset;
	targetFreeAddr = targetLibcAddr + freeOffset;
	targetDlopenAddr = targetLibcAddr + dlopenOffset;

	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	ptrace_attach(target);
	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	/* check the stack activeness */
	long curr = oldregs.rip;
	if (!checkstack(target, oldregs.rip, origLibName)) {
		ptrace_detach(target);
		return 1;
	}

	/* find a good address and copy target_snippet() to it*/
	addr = freespaceaddr(target) + sizeof(long);
	backup = calloc(1, target_snippet_size * sizeof(char));
	target_snippet_size = inject_target_snippet(target, addr, backup);

	/* set the target's rip to it. we have to advance by 2 bytes here
	 * because rip gets incremented by the size of the current instruction,
	 * and the instruction at the start of the function to inject always
	 * happens to be 2 bytes long.
	 *
	 * accroding to x64 calling convention, arguments are passed via REGs
	 * rdi, rsi, rdx, rcx, r8, and r9. see comments in target_snippet()
	 * for more details.
	 */
	regs.rip = addr + 2;
	regs.r9 = targetMallocAddr;
	regs.rdi = libPathLength;
	ptrace_setregs(target, &regs);

	/* call malloc() */
	ptrace_cont(target);

	/* the target process malloc() returns. check wether it succeeded */
	memset(&target_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &target_regs);
	targetBuf = target_regs.rax;
	if (targetBuf == 0) {
		error = 1;
		fprintf(stderr, "malloc() failed to allocate memory\n");
		goto end;
	}

	/* malloc() succeeded, copy path of shared lib into the malloc'd
	 * buffer. 
	 */
	ptrace_write(target, targetBuf, libPath, libPathLength);

	/* continue the target's execution and call __libc_dlopen_mode. */
	regs.rip = addr + 2;
	regs.r9 = targetDlopenAddr;
	regs.rdi = targetBuf;
	regs.rsi = 1;

	ptrace_setregs(target, &regs);
	ptrace_cont(target);

	memset(&target_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &target_regs);
	libAddr = target_regs.rax;

	/* if rax is 0 here, dlopen() failed, bail out cleanly. */
	if (libAddr == 0) {
		error = 1;
		fprintf(stderr, "dlopen() failed to load %s\n", libname);
		goto end;
	}

	/* now check /proc/pid/maps to see whether injection succecced. */
	if (checkloaded(target, libname))
		printf("\"%s\" successfully injected\n", libname);
	else {
		error = 1;
		fprintf(stderr, "could not inject \"%s\"\n", libname);
		goto end;
	}

	/* call free() and we don't care whether this succeeds, so don't
	 * bother checking the return value.
	 */
	regs.rip = addr + 2;
	regs.r9 = targetFreeAddr;
	regs.rdi = targetBuf;
	ptrace_setregs(target, &regs);
	ptrace_cont(target);

end:
	/* restore the old state and detach from the target. */
	restoreStateAndDetach(target, addr, backup,
			target_snippet_size, oldregs);
	free(backup);
	return error;
}
