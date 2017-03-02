#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>

#include "utils.h"
#include "ptrace.h"

void target_inject(void) { 
	asm("push %r9 \n"
	"callq *%r9 \n"
	"pop %r9 \n"
	);
}

void target_inject_end() {
}

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
	struct user_regs_struct malloc_regs;
	struct user_regs_struct dlopen_regs;
	long addr;
	size_t target_inject_size;
	intptr_t target_inject_ret;
	char *backup, *newcode;
	unsigned long long targetBuf;
	unsigned long long libAddr;

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

	/* find a good address to copy code to */
	addr = freespaceaddr(target) + sizeof(long);

	target_inject_size = (intptr_t)target_inject_end -
		(intptr_t)target_inject;

	/* also figure out where the RET instruction at the end of
	 * injectSharedLibrary() lies and overwrite it with an INT 3
	 * in order to break back into the target process. note that on x64,
	 * gcc force function addresses to be word-aligned,
	 * which means that functions are padded with NOPs. as a result, even
	 * though we've found the length of the function, it is very likely
	 * padded with NOPs, so we need to actually search to find the RET.
	 */
	target_inject_ret = (intptr_t)findRet(target_inject_end) -
		(intptr_t)target_inject;

	/* back up whatever data at the address we want to modify. */
	backup = malloc(target_inject_size * sizeof(char));
	ptrace_read(target, addr, backup, target_inject_size);

	/* set up a buffer and copy injectSharedLibrary() code into the
	 * target process.
	 */
	newcode = calloc(1, target_inject_size * sizeof(char));
	memcpy(newcode, target_inject, target_inject_size - 1);
	/* overwrite the RET instruction with an INT 3. */
	newcode[target_inject_ret] = INTEL_INT3_INSTRUCTION;

	/* copy injectSharedLibrary()'s code to the target address inside the
	 * target process' address space.
	 */
	ptrace_write(target, addr, newcode, target_inject_size);
	free(newcode);

	/* will copy injectSharedLibrary() to this addr, set the target's rip to
	 * it. we have to advance by 2 bytes here because rip gets incremented
	 * by the size of the current instruction, and the instruction at the
	 * start of the function to inject always happens to be 2 bytes long.
	 *
	 * accroding to x64 calling convention, arguments are passed via REGs
	 * rdi, rsi, rdx, rcx, r8, and r9. see comments in injectSharedLibrary()
	 * for more details.
	 */
	regs.rip = addr + 2;
	regs.r9 = targetMallocAddr;
	regs.rdi = libPathLength;
	ptrace_setregs(target, &regs);

	/* call malloc() */
	ptrace_cont(target);

	/* the target process malloc() returns. check wether it succeeded */
	memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &malloc_regs);
	targetBuf = malloc_regs.rax;
	if (targetBuf == 0) {
		fprintf(stderr, "malloc() failed to allocate memory\n");
		restoreStateAndDetach(target, addr, backup,
				target_inject_size, oldregs);
		free(backup);
		return 1;
	}

	/* malloc() succeeded, copy path of shared lib into the malloc'd
	 * buffer. 
	 */
	ptrace_write(target, targetBuf, libPath, libPathLength);

	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));
	regs.rip = addr + 2;
	regs.r9 = targetDlopenAddr;
	regs.rdi = targetBuf;
	regs.rsi = 1;

	ptrace_setregs(target, &regs);

	/* continue the target's execution and call __libc_dlopen_mode. */
	ptrace_cont(target);

	memset(&dlopen_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &dlopen_regs);
	libAddr = dlopen_regs.rax;

	/* if rax is 0 here, dlopen() failed, bail out cleanly. */
	if (libAddr == 0) {
		fprintf(stderr, "__libc_dlopen_mode() failed to load %s\n",
				libname);
		restoreStateAndDetach(target, addr, backup,
				target_inject_size, oldregs);
		return 1;
	}

	/* now check /proc/pid/maps to see whether injection succecced. */
	if (checkloaded(target, libname))
		printf("\"%s\" successfully injected\n", libname);
	else {
		fprintf(stderr, "could not inject \"%s\"\n", libname);
		restoreStateAndDetach(target, addr, backup,
				target_inject_size, oldregs);
		free(backup);
		return 1;
	}

	/* call free() and we don't care whether this succeeds, so don't
	 * bother checking the return value.
	 */
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));
	regs.rip = addr + 2;
	regs.r9 = targetFreeAddr;
	regs.rdi = targetBuf;
	ptrace_setregs(target, &regs);
	ptrace_cont(target);

	/* restore the old state and detach from the target. */
	restoreStateAndDetach(target, addr, backup,
			target_inject_size, oldregs);
	free(backup);

	return 0;
}
