#include <errno.h>
#include <libunwind-ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#if defined __x86_64__
    #define SYSCALL_NUM orig_rax
#else
    #error Only x86_64 is supported.
#endif


#define WARN(...)  do { fprintf(stderr, __VA_ARGS__); } while (0)
#define FATAL(...) do { fprintf(stderr, __VA_ARGS__); return EXIT_FAILURE; } while (0)
#define PANIC(...) do { fprintf(stderr, __VA_ARGS__); goto CLEANUP; } while (0)

int
main(int argc, char** argv)
{
    if (argc < 2)
        FATAL("usage: %s <pid>\n", argv[0]);

    pid_t pid = atoi(argv[1]);
    if (!pid)
        FATAL("bad pid %d\n", pid);
    if (kill(pid, 0) < 0)
        FATAL("couldn't signal process %d: %s\n", pid, strerror(errno));

    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!as)
        FATAL("unw_create_addr_space() failed");
    unw_set_caching_policy(as, UNW_CACHE_GLOBAL);

    struct UPT_info* ui = _UPT_create (pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        FATAL("PTRACE_ATTACH failed: %s\n", strerror(errno));

    // go through loop twice per syscall, once on entry and again on exit
    int state, interesting;
    for (state = 1; ; state ^= 1) {
        int status;
        if (waitpid(-1, &status, 0) < 0) {
            if (errno == EINTR)
                continue;
            PANIC("waitpid() failed: %s\n", strerror(errno));
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        int pending_sig = 0;
        if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
            pending_sig = WSTOPSIG(status);
            if (WSTOPSIG(status) == SIGKILL)
                break;
        }

        if (state) {
            // copy args on syscall entry
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            interesting = (regs.SYSCALL_NUM == SYS_brk) || 0;
            //printf("syscall %ld: %s\n", regs.SYSCALL_NUM, x86_64_syscalls[regs.SYSCALL_NUM]);
        }
        else if (interesting) {
            // display backtrace
            unw_word_t ip, sp, start_ip = 0, off;
            int n = 0, ret;
            unw_proc_info_t pi;
            unw_cursor_t c;
            char buf[512];
            size_t len;

            ret = unw_init_remote(&c, as, ui);
            if (ret < 0)
                PANIC("unw_init_remote() failed: ret=%d\n", ret);

            do {
                if ((ret = unw_get_reg(&c, UNW_REG_IP, &ip)) < 0
                        || (ret = unw_get_reg(&c, UNW_REG_SP, &sp)) < 0)
                    PANIC("unw_get_reg/unw_get_proc_name() failed: ret=%d\n", ret);

                if (n == 0)
                    start_ip = ip;

                buf[0] = '\0';
                unw_get_proc_name(&c, buf, sizeof (buf), &off);

                if (off) {
                    len = strlen(buf);
                    if (len >= sizeof(buf) - 32)
                        len = sizeof(buf) - 32;
                    sprintf(buf + len, "+0x%lx", (unsigned long) off);
                }
                printf("%016lx %-32s (sp=%016lx)\n", (long) ip, buf, (long) sp);

                if ((ret = unw_get_proc_info(&c, &pi)) < 0)
                    PANIC("unw_get_proc_info(ip=0x%lx) failed: ret=%d\n", (long) ip, ret);
                else
                    printf("\tproc=%016lx-%016lx\n\thandler=%lx lsda=%lx\n",
                           (long) pi.start_ip, (long) pi.end_ip,
                           (long) pi.handler, (long) pi.lsda);

                ret = unw_step(&c);
                if (ret < 0) {
                    unw_get_reg(&c, UNW_REG_IP, &ip);
                    PANIC("FAILURE: unw_step() returned %d for ip=%lx (start ip=%lx)\n",
                          ret, (long) ip, (long) start_ip);
                }

                if (++n > 64) {
                    /* guard against bad unwind info in old libraries... */
                    PANIC("too deeply nested---assuming bogus unwind (start ip=%lx)\n",
                          (long) start_ip);
                    break;
                }
            } while (ret > 0);
            printf("\n");

            if (ret < 0)
                PANIC("unwind failed with ret=%d\n", ret);
        }

        if (ptrace(PTRACE_SYSCALL, pid, pending_sig, NULL) < 0)
            PANIC("PTRACE_SYSCALL: %s\n", strerror(errno));
    }

    CLEANUP:
    ptrace(PTRACE_DETACH, pid, (char*) 1, 0);
    _UPT_destroy (ui);
    unw_destroy_addr_space(as);

    return EXIT_SUCCESS;
}
