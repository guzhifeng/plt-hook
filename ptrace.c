#include <errno.h>
#include "ptrace.h"

/*
 * ptrace_attach()
 *
 * Use ptrace() to attach to a process. This requires calling waitpid()
 * to determine when the process is ready to be traced.
 *
 * args:
 * - pid_t target: pid of the process to attach to
 *
 */

int ptrace_attach(pid_t target)
{
	if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
		fprintf(stderr, "ptrace(PTRACE_ATTACH) failed\n");
		return -errno;
	}

	return 0;
}

/*
 * ptrace_detach()
 *
 * Detach from a process that is being ptrace()d. Unlike ptrace_cont(),
 * this completely ends our relationship with the target process.
 *
 * args:
 * - pid_t target: pid of the process to detach from.
 *
 */

int ptrace_detach(pid_t target)
{
	if (ptrace(PTRACE_DETACH, target, NULL, NULL) == -1) {
		fprintf(stderr, "ptrace(PTRACE_DETACH) failed\n");
		return -errno;
	}

	return 0;
}

/*
 * ptrace_getregs()
 *
 * Use ptrace() to get a process' current register state.  Uses REG_TYPE
 * preprocessor macro in order to allow for both ARM and x86/x86_64
 * functionality.
 *
 * args:
 * - pid_t target: pid of the target process
 * - struct REG_TYPE* regs: a struct (either user_regs_struct or user_regs,
 *   depending on architecture) to store the resulting register data in
 *
 */

int ptrace_getregs(pid_t target, struct REG_TYPE *regs)
{
	if (ptrace(PTRACE_GETREGS, target, NULL, regs) == -1) {
		fprintf(stderr, "ptrace(PTRACE_GETREGS) failed\n");
		return -errno;
	}

	return 0;
}

/*
 * ptrace_cont()
 *
 * Continue the execution of a process being traced using ptrace(). Note that
 * this is different from ptrace_detach(): we still retain control of the
 * target process after this call.
 *
 * args:
 * - pid_t target: pid of the target process
 *
 */

int ptrace_cont(pid_t target)
{
	struct timespec *sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 0;
	sleeptime->tv_nsec = 50000000;

	if (ptrace(PTRACE_CONT, target, NULL, NULL) == -1) {
		fprintf(stderr, "ptrace(PTRACE_CONT) failed\n");
		return -errno;
	}

	nanosleep(sleeptime, NULL);

	/* make sure the target process received SIGTRAP after stopping. */
	if ((checktargetsig(target)) < 0) {
		printf("checktargetsig failed, wait longer please!\n");
		return -1;
	}
	return 0;
}

/*
 * ptrace_setregs()
 *
 * Use ptrace() to set the target's register state.
 *
 * args:
 * - int pid: pid of the target process
 * - struct REG_TYPE* regs: a struct (either user_regs_struct or user_regs,
 *   depending on architecture) containing the register state to be set in the
 *   target process
 *
 */

int ptrace_setregs(pid_t target, struct REG_TYPE *regs)
{
	if (ptrace(PTRACE_SETREGS, target, NULL, regs) == -1) {
		fprintf(stderr, "ptrace(PTRACE_SETREGS) failed\n");
		return -errno;
	}

	return 0;
}

/*
 * ptrace_getsiginfo()
 *
 * Use ptrace() to determine what signal was most recently raised by the target
 * process. This is primarily used for to determine whether the target process
 * has segfaulted.
 *
 * args:
 * - int pid: pid of the target process
 *
 * returns:
 * - a siginfo_t containing information about the most recent signal raised by
 *   the target process
 *
 */

int ptrace_getsiginfo(pid_t target, siginfo_t *targetsig)
{
	if (ptrace(PTRACE_GETSIGINFO, target, NULL, targetsig) == -1) {
		fprintf(stderr, "ptrace(PTRACE_GETSIGINFO) failed\n");
		return -errno;
	}

	return 0;
}

/*
 * ptrace_read()
 *
 * Use ptrace() to read the contents of a target process' address space.
 *
 * args:
 * - int pid: pid of the target process
 * - unsigned long addr: the address to start reading from
 * - void *vptr: a pointer to a buffer to read data into
 * - int len: the amount of data to read from the target
 *
 */

int ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
	int bytesRead = 0;
	int i = 0;
	long word = 0;
	long *ptr = (long *) vptr;

	while (bytesRead < len) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
		if (word == -1) {
			fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
			return -errno;
		}
		bytesRead += sizeof(word);
		ptr[i++] = word;
	}

	return 0;
}

/*
 * ptrace_write()
 *
 * Use ptrace() to write to the target process' address space.
 *
 * args:
 * - int pid: pid of the target process
 * - unsigned long addr: the address to start writing to
 * - void *vptr: a pointer to a buffer containing the data to be written to the
 *   target's address space
 * - int len: the amount of data to write to the target
 *
 */

int ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
	int byteCount = 0;
	long word = 0;

	while (byteCount < len) {
		memcpy(&word, vptr + byteCount, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
		if (word == -1) {
			fprintf(stderr, "ptrace(PTRACE_POKETEXT) failed\n");
			return -errno;
		}
		byteCount += sizeof(word);
	}

	return 0;
}

/*
 * checktargetsig()
 *
 * Check what signal was most recently returned by the target process being
 * ptrace()d. We expect a SIGTRAP from the target process, so raise an error
 * and exit if we do not receive that signal. The most likely non-SIGTRAP
 * signal for us to receive would be SIGSEGV.
 *
 * args:
 * - pid_t target: pid of the target process
 *
 */

int checktargetsig(pid_t target)
{
	siginfo_t targetsig;
	/* check the signal that the child stopped with. */
	if (ptrace_getsiginfo(target, &targetsig) < 0)
		return -errno;

	/* if it's not SIGTRAP, something wrong(most likely a segfault). */
	if (targetsig.si_signo != SIGTRAP) {
		printf("expected SIGTRAP, but target stopped with sig %d: %s\n",
			targetsig.si_signo, strsignal(targetsig.si_signo));
		printf("sending proc %d a SIGSTOP for debugging\n", target);
		if (ptrace(PTRACE_CONT, target, NULL, SIGSTOP) == -1)
			return -errno;
	}

	return 0;
}
