#include <errno.h>
#include <libunwind-ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined __x86_64__
    // http://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
    // http://www.x86-64.org/documentation/abi.pdf
    #define SYSCALL_ARG1        rdi
    #define SYSCALL_ARG2        rsi
    #define SYSCALL_ARG3        rdx
    #define SYSCALL_ARG4        r10
    #define SYSCALL_ARG5        r8
    #define SYSCALL_ARG6        r9
    #define SYSCALL_NUM_OFFSET  (8*ORIG_RAX)
    #define SYSCALL_RET_OFFSET  (8*RAX)
#else
    #error Only x86_64 supported.
#endif


#define WARN(...)  do { fprintf(stderr, __VA_ARGS__); } while (0)
#define FATAL(...) do { fprintf(stderr, __VA_ARGS__); return EXIT_FAILURE; } while (0)
#define PANIC(...) do { fprintf(stderr, __VA_ARGS__); goto CLEANUP; } while (0)

int stopped = 0;
void handler(int sig) {
    if (sig == SIGINT)
        if (stopped++)
            _exit(-1);
}

int
main(int argc, char** argv)
{
    if (argc < 2)
        FATAL("usage: %s <pid> [<exe>]\n", argv[0]);

    pid_t pid = atoi(argv[1]);
    if (!pid)
        FATAL("bad pid %d\n", pid);
    if (kill(pid, 0) < 0)
        FATAL("couldn't signal process %d: %s\n", pid, strerror(errno));

    const char* image = NULL;
    if (argc > 2)
        image = argv[2];

    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!as)
        FATAL("unw_create_addr_space() failed");
    unw_set_caching_policy(as, UNW_CACHE_GLOBAL);

    struct UPT_info* ui = _UPT_create (pid);

    signal(SIGINT, handler);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        FATAL("PTRACE_ATTACH failed: %s\n", strerror(errno));

    int entering; // go through loop twice per syscall, once on entry and again on exit
    void* last_brk = NULL;
    for (entering = 1; !stopped; entering = !entering) {
        int status;
        if (waitpid(-1, &status, 0) < 0) {
            if (errno == EINTR)
                continue;
            PANIC("waitpid() failed: %s\n", strerror(errno));
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        int pending_sig = 0, show_backtrace = 0;
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGSTOP)
                entering = 0;
            else if (sig == SIGKILL)
                break;
            else if (sig != SIGTRAP)
                pending_sig = sig;
            else { // SIGTRAP
                long syscall, retval;
                struct user_regs_struct regs;
                syscall = ptrace(PTRACE_PEEKUSER, pid, SYSCALL_NUM_OFFSET, NULL);
                retval = ptrace(PTRACE_PEEKUSER, pid, SYSCALL_RET_OFFSET, NULL);
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);

                if (!entering) {
                    if (syscall == SYS_brk) {
                        void* new_brk = (void*) retval;
                        if (last_brk == NULL)
                            printf("brk is at %p\n", new_brk);
                        else if (new_brk == last_brk)
                            printf("brk unchanged at %p\n", new_brk);
                        else
                            printf("new brk is at %p (%ld bytes more)\n", new_brk, new_brk - last_brk);
                        last_brk = new_brk;
                        show_backtrace = 1;
                    }
                    else if (syscall == SYS_mmap) {
                        void* addr = (void*) retval;
                        int len = (int) regs.SYSCALL_ARG2;
                        int prot = (int) regs.SYSCALL_ARG3;
                        int flags = (int) regs.SYSCALL_ARG4;
                        if (prot & PROT_READ && prot & PROT_WRITE &&
                            flags & MAP_PRIVATE && flags & MAP_ANONYMOUS
                        ) {
                            show_backtrace++;
                            printf("new anonymous mmap of %d bytes at %p\n", len, addr);
                        }
                    }
                }
            }
        }

        if (show_backtrace) {
            unw_word_t ip, sp, start_ip = 0, off;
            int n = 0, ret;
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
                unw_get_proc_name(&c, buf, sizeof(buf), &off);

                if (off) {
                    len = strlen(buf);
                    if (len >= sizeof(buf) - 32)
                        len = sizeof(buf) - 32;
                    sprintf(buf + len, "+0x%lx", (unsigned long) off);
                }
                printf("%016lx %-32s (sp=%016lx)\n", (long) ip, buf, (long) sp);

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
                }

                if (image) {
                    char addr2line[128];
                    snprintf(addr2line, sizeof(addr2line), "addr2line -C -e %s -i %lx", image, ip);
                    int ret = system(addr2line) < 0;
                    if (ret < 0)
                        WARN("addr2line failed: %s\n", strerror(errno));
                }
            } while (ret > 0);
            printf("\n");
        }

        if (ptrace(PTRACE_SYSCALL, pid, NULL, pending_sig) < 0)
            PANIC("PTRACE_SYSCALL: %s\n", strerror(errno));
    }

    CLEANUP:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    _UPT_destroy (ui);
    unw_destroy_addr_space(as);

    return EXIT_SUCCESS;
}
