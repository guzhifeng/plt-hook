#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>

#include "utils.h"
#include "ptrace.h"

/*
 * injectSharedLibrary()
 *
 * This is the code that will actually be injected into the target process.
 * This code is responsible for loading the shared library into the target
 * process' address space.  First, it calls malloc() to allocate a buffer to
 * hold the filename of the library to be loaded. Then, it calls
 * __libc_dlopen_mode(), libc's implementation of dlopen(), to load the desired
 * shared library. Finally, it calls free() to free the buffer containing the
 * library name. Each time it needs to give control back to the injector
 * process, it breaks back in by executing an "int $3" instruction. See the
 * comments below for more details on how this works.
 *
 */

void injectSharedLibrary(long mallocaddr, long freeaddr, long dlopenaddr)
{
	/* rdi = address of malloc() in target process
	 * rsi = address of free() in target process
	 * rdx = address of __libc_dlopen_mode() in target process
	 * rcx = size of the path of shared library we want to load
	 */

	/* save addr of free() and __libc_dlopen_mode() for later use */
	asm("push %rsi \n"
		"push %rdx");

	/* call malloc(), R9 play a role as intermediate register */
	asm("push %r9 \n"
		"mov %rdi,%r9 \n"
		"mov %rcx,%rdi \n"
		"callq *%r9 \n"
		"pop %r9 \n"
		/* break in so that we can see what malloc() returned */
		"int $3"
	);

	/* call __libc_dlopen_mode((void *)dsoname, RTLD_LAZY) */
	asm(
		/* pop addr__libc_dlopen_mode() from the stack */
		"pop %rdx \n"
		"push %r9 \n"
		"mov %rdx,%r9 \n"
		"mov %rax,%rdi \n"
		"movabs $1,%rsi \n"
		"callq *%r9 \n"
		"pop %r9 \n"
		"int $3"
	);

	/* call free() to free the buffer we allocated earlier.
	 * Note: I found that if you put a nonzero value in r9, free() seems to
	 * interpret that as an address to be freed, even though it's only
	 * supposed to take one argument. As a result, I had to call it using a
	 * register that's not used as part of the x64 calling convention. I
	 * chose rbx.
	 */
	asm(
		/* rax contain our malloc()d buffer */
		"mov %rax,%rdi \n"
		/* pop address of free() from stack */
		"pop %rsi \n"
		"push %rbx \n"
		"mov %rsi,%rbx \n"
		/* zero out rsi, because free() might think that it contains
		 * something that should be freed
		 */
		"xor %rsi,%rsi \n"
		/* break in so we can check the arguments before making the call */
		"int $3 \n"
		/* call free() */
		"callq *%rbx \n"
		/* restore previous rbx value */
		"pop %rbx"
	);

/* we already overwrote the RET instruction at the end of this function
 * with an INT 3, so at this point the injector will regain control of
 * the target's execution.
 */
}

/*
 * injectSharedLibrary_end()
 *
 * This function's only purpose is to be contiguous to injectSharedLibrary(),
 * so that we can use its address to more precisely figure out how long
 * injectSharedLibrary() is.
 *
 */
void injectSharedLibrary_end(void)
{
}

int main(int argc, char **argv)
{
	char *command, *commandArg;
	char *libname, *libPath;
	char *processName;
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
	size_t injectSharedLibrary_size;
	intptr_t injectSharedLibrary_ret;
	char *backup, *newcode;
	unsigned long long targetBuf;
	unsigned long long libAddr;

	if (argc < 4) {
		usage(argv[0]);
		return 1;
	}

	command = argv[1];
	commandArg = argv[2];
	libname = argv[3];
	libPath = realpath(libname, NULL);

	processName = NULL;

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
	mylibcaddr = getlibcaddr(mypid);

	/* find the addresses of the syscalls that we'd like to use inside the
	 * target, as loaded inside THIS process (i.e. NOT the target process)
	 */
	mallocAddr = getFunctionAddress("malloc");
	freeAddr = getFunctionAddress("free");
	dlopenAddr = getFunctionAddress("__libc_dlopen_mode");

	/* use the base address of libc to calculate offsets for the syscalls
	 * we want to use
	 */
	mallocOffset = mallocAddr - mylibcaddr;
	freeOffset = freeAddr - mylibcaddr;
	dlopenOffset = dlopenAddr - mylibcaddr;

	/* get the target process' libc function address */
	targetLibcAddr = getlibcaddr(target);
	targetMallocAddr = targetLibcAddr + mallocOffset;
	targetFreeAddr = targetLibcAddr + freeOffset;
	targetDlopenAddr = targetLibcAddr + dlopenOffset;

	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	ptrace_attach(target);

	ptrace_getregs(target, &oldregs);

	/* check the stack */
	{
	}

	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	/* find a good address to copy code to */
	addr = freespaceaddr(target) + sizeof(long);

	/* will copy injectSharedLibrary() to this addr, set the target's rip to
	 * it. we have to advance by 2 bytes here because rip gets incremented
	 * by the size of the current instruction, and the instruction at the
	 * start of the function to inject always happens to be 2 bytes long.
	 */
	regs.rip = addr + 2;

	/*
	 * accroding to x64 calling convention, arguments are passed via REGs
	 * rdi, rsi, rdx, rcx, r8, and r9. see comments in injectSharedLibrary()
	 * for more details.
	 */
	regs.rdi = targetMallocAddr;
	regs.rsi = targetFreeAddr;
	regs.rdx = targetDlopenAddr;
	regs.rcx = libPathLength;
	ptrace_setregs(target, &regs);

	injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end -
		(intptr_t)injectSharedLibrary;

	/* also figure out where the RET instruction at the end of
	 * injectSharedLibrary() lies and overwrite it with an INT 3
	 * in order to break back into the target process. note that on x64,
	 * gcc force function addresses to be word-aligned,
	 * which means that functions are padded with NOPs. as a result, even
	 * though we've found the length of the function, it is very likely
	 * padded with NOPs, so we need to actually search to find the RET.
	 */
	injectSharedLibrary_ret = (intptr_t)findRet(injectSharedLibrary_end) -
		(intptr_t)injectSharedLibrary;

	/* back up whatever data at the address we want to modify. */
	backup = malloc(injectSharedLibrary_size * sizeof(char));
	ptrace_read(target, addr, backup, injectSharedLibrary_size);

	/* set up a buffer and copy injectSharedLibrary() code into the
	 * target process.
	 */
	newcode = calloc(1, injectSharedLibrary_size * sizeof(char));
	memcpy(newcode, injectSharedLibrary, injectSharedLibrary_size - 1);
	/* overwrite the RET instruction with an INT 3. */
	newcode[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION;

	/* copy injectSharedLibrary()'s code to the target address inside the
	 * target process' address space.
	 */
	ptrace_write(target, addr, newcode, injectSharedLibrary_size);

	/* let the target run our injected code. */
	ptrace_cont(target);

	/* the target process malloc() returns. check wether it succeeded */
	memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &malloc_regs);
	targetBuf = malloc_regs.rax;
	if (targetBuf == 0) {
		fprintf(stderr, "malloc() failed to allocate memory\n");
		restoreStateAndDetach(target, addr, backup,
				injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	/* malloc() succeeded, copy path of shared lib into the malloc'd
	 * buffer. 
	 */
	ptrace_write(target, targetBuf, libPath, libPathLength);

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
				injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	/* now check /proc/pid/maps to see whether injection succecced. */
	if (checkloaded(target, libname))
		printf("\"%s\" successfully injected\n", libname);
	else
		fprintf(stderr, "could not inject \"%s\"\n", libname);

	/* call free() and we don't care whether this succeeds, so don't
	 * bother checking the return value.
	 */
	ptrace_cont(target);

	/* restore the old state and detach from the target. */
	restoreStateAndDetach(target, addr, backup,
			injectSharedLibrary_size, oldregs);
	free(backup);
	free(newcode);

	return 0;
}
