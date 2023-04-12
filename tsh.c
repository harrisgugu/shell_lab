/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Tianlang Gu <tianlang@andrew.cmu.edu>
 * TODO: Include your name and Andrew ID here.
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);
void unix_error(char *msg);
void wait_fg(pid_t pid, sigset_t prevmask);
void bg_fg_opr(char **argv, int bg, sigset_t *prevmask);

int prev_STDOUT, prev_STDIN;
// volatile sig_atomic_t fgflag;
/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function
 * makes."
 */

pid_t Fork(void) {
    pid_t pid;
    if ((pid = fork()) < 0)
        unix_error("Fork error");
    return pid;
}

int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    prev_STDOUT = STDOUT_FILENO;
    prev_STDIN = STDIN_FILENO;
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            sio_printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            sio_printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */

void bg_fg_opr(char **argv, int bg, sigset_t *prevmask) {
    pid_t pid = -1;
    jid_t jid = -1;
    if (argv[1] == NULL) {
        sio_printf("%s command requires PID or %%jobid argument\n", argv[0]);
        return;
    }
    if (sscanf(argv[1], "%%%d", &jid) > 0) {
        if (!job_exists(jid)) {
            sio_printf("%%%d: No such job\n", jid);
            return;
        }
        pid = job_get_pid(jid);
    } else if (sscanf(argv[1], "%d", &pid) > 0) {
        jid = job_from_pid(pid);
        if (!job_exists(jid)) {
            sio_printf("(%d): No such process\n", jid);
            return;
        }
    } else {
        sio_printf("%s: argument must be a PID or %%jobid\n", argv[0]);
        return;
    }
    // if (pid == -1 || jid == -1) {
    //         sio_printf("%s: argument must be a PID or %%jobid argument\n",
    //                    argv[0]);
    //         return;
    // }
    // printf("%d jid from print line\n", jid);
    if (bg) {
        job_state currstate = job_get_state(jid);
        if (currstate == BG) {
            sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
            return;
        }
        if (currstate == ST) {
            // signal the whole group
            kill(pid, SIGCONT);
            kill(-pid, SIGCONT);
            job_set_state(jid, BG);
            sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
        }
        // kill(pid, SIGCONT);
        // kill(-pid, SIGCONT);
        // job_set_state(jid, BG);
        // printf("[%d] (%d) %s", jid, pid, job_get_cmdline(jid));
        return;
    } else {

        // job_state currstate = job_get_state(jid);
        //  if (currstate == ST) {
        //      kill(pid, SIGCONT);
        //      kill(-pid, SIGCONT);
        //  }
        kill(pid, SIGCONT);
        kill(-pid, SIGCONT);

        job_set_state(jid, FG);
        // wait_fg(pid, prevmask);
        //  wait_fg(pid);
        while (fg_job() != 0) {

            sigsuspend(prevmask);
            // pid_t fpid = fg_job();
        }
        return;
    }
}

// function to handle the foreground process
void wait_fg(pid_t pid, sigset_t prevmask) {
    // sigset_t mask, prevmask;
    // sigemptyset(&mask);
    // sigfillset(&mask);

    while (fg_job() != 0) {

        sigsuspend(&prevmask);
        // pid_t fpid = fg_job();
    }

    return;
}

void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    // Parse command line
    parse_result = parseline(cmdline, &token);
    // printf("cmd line: %d\n", token.builtin);
    pid_t pid;
    // pid_t currpid;
    sigset_t mask, prevmask;
    int outfile = -1;
    int infile = -1;
    jid_t jid;
    // struct job_t *currjob;
    //  struct job_t *job,*bg_job;
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }
    // sigemptyset(&mask);
    // sigemptyset(&prevmask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);
    sigprocmask(SIG_BLOCK, &mask, &prevmask);

    switch (token.builtin) {
    case BUILTIN_QUIT:

        sigprocmask(SIG_SETMASK, &prevmask, NULL);
        exit(0);
    case BUILTIN_BG:
        // printf("background\n");
        bg_fg_opr(token.argv, 1, &prevmask);
        sigprocmask(SIG_SETMASK, &prevmask, NULL);
        break;
    case BUILTIN_FG:
        // printf("foreground\n");
        bg_fg_opr(token.argv, 0, &prevmask);
        sigprocmask(SIG_SETMASK, &prevmask, NULL);

        break;
    case BUILTIN_NONE:
        dbg_printf("Not a builtin command\n");

        //  if it is a child process

        if ((pid = Fork()) == 0) {

            // child process

            sigprocmask(SIG_SETMASK, &prevmask, NULL);
            setpgid(0, 0);

            if (token.infile != NULL) {
                infile = open(token.infile, O_RDONLY, DEF_MODE);
                if (infile < 0) {
                    perror(token.infile);
                    sigprocmask(SIG_SETMASK, &prevmask, NULL);
                    exit(0);
                    // break;
                }
                dup2(infile, STDIN_FILENO);
            }
            if (token.outfile != NULL) {
                outfile = creat(token.outfile, 0644);
                if (outfile < 0) {
                    perror(token.outfile);
                    sigprocmask(SIG_SETMASK, &prevmask, NULL);
                    exit(0);
                    // break;
                }
                dup2(outfile, STDOUT_FILENO);
            }
            if (execve(token.argv[0], token.argv, environ) < 0) {
                perror(token.argv[0]);
                // sio_printf("%s: Permission denied.\n", token.argv[0]);
                exit(0);
            }
            // sigprocmask(SIG_BLOCK, &mask, &prevmask);

        } else {

            // parent process

            if (parse_result == PARSELINE_FG) {
                // when the foreground is running
                // jid =
                jid = add_job(pid, FG, cmdline);
                //
                wait_fg(pid, prevmask);

            } else {
                // when the background is running

                // jid =
                jid = add_job(pid, BG, cmdline);
                sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
            }

            // unix_error("waitfg: waitpid error");

            sigprocmask(SIG_SETMASK, &prevmask, NULL);
        }
        break;

    case BUILTIN_JOBS:
        // sio_printf("jobs reached\n");
        if (token.outfile != NULL) {
            outfile = open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (outfile < 0) {
                // if (errno == EACCES) {
                //     sio_printf("%s: Permission Denied", token.outfile);
                // }
                perror(token.outfile);
                // dup2(prev_STDOUT, STDOUT_FILENO);
                // dup2(prev_STDIN, STDIN_FILENO);
                sigprocmask(SIG_SETMASK, &prevmask, NULL);
                // exit(0);
                break;
            }
            list_jobs(outfile);
        } else {
            list_jobs(STDOUT_FILENO);
        }
        // list_jobs(STDOUT_FILENO);
        dup2(prev_STDIN, STDIN_FILENO);
        dup2(prev_STDOUT, STDOUT_FILENO);
        sigprocmask(SIG_SETMASK, &prevmask, NULL);
        break;
    default:
        sigprocmask(SIG_SETMASK, &prevmask, NULL);
        break;
    }
    if (infile >= 0) {
        close(infile);
        dup2(dup(STDIN_FILENO), STDIN_FILENO);
    }
    if (outfile >= 0) {
        close(outfile);
        dup2(dup(STDOUT_FILENO), STDOUT_FILENO);
    }
    return;
    // TODO: Implement commands here.
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief <What does sigchld_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigchld_handler(int sig) {
    int preverrno = errno;
    int status;
    pid_t cpid;
    sigset_t mask, prevmask;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prevmask);
    // pid_t fpid = fg_job();
    while ((cpid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        // if(cpid==fpid)
        //     fgflag = 1;//set the flag to 1 to stop the while loop
        if (WIFSIGNALED(status)) {
            // if the signal is interrupted
            jid_t jid = job_from_pid(cpid);
            // jid_t fjid = fg_job();
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, cpid,
                       WTERMSIG(status));
            delete_job(jid);
        } else if (WIFEXITED(status)) {
            jid_t jid = job_from_pid(cpid);
            // printf("Job [%d] (%d) terminated by signal %d\n", jid, fpid,
            //        WTERMSIG(status));
            delete_job(jid);
        } else if (WIFSTOPPED(status)) {
            jid_t jid = job_from_pid(cpid);
            // struct job_t *jobp = get_job(jid);
            // jid_t fjid = fg_job();
            job_set_state(jid, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, cpid,
                       WSTOPSIG(status));
            // delete_job(jid);
        }
    }
    sigprocmask(SIG_SETMASK, &prevmask, NULL);
    errno = preverrno;
    return;
}

/**
 * @brief <What does sigint_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigint_handler(int sig) {
    int preverrno = errno;
    sigset_t mask, prevmask;
    // sigemptyset(&prevmask);
    // sigemptyset(&mask);
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prevmask);
    jid_t jid = fg_job();
    if (jid != 0) {
        pid_t fpid = job_get_pid(jid);
        if (fpid != 0) {
            kill(fpid, SIGINT);
            kill(-fpid, SIGINT);
        }
    }
    sigprocmask(SIG_SETMASK, &prevmask, NULL);
    errno = preverrno;
    return;
}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigtstp_handler(int sig) {
    int preverrno = errno;
    sigset_t mask, prevmask;
    sigfillset(&mask);
    // sigemptyset(&prevmask);
    sigprocmask(SIG_BLOCK, &mask, &prevmask);
    jid_t jid = fg_job();
    if (jid != 0) {
        pid_t fpid = job_get_pid(jid);
        if (fpid != 0) {
            kill(fpid, SIGTSTP);
            kill(-fpid, SIGTSTP);
        }
    }
    sigprocmask(SIG_SETMASK, &prevmask, NULL);
    errno = preverrno;
    return;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}

void unix_error(char *msg) {
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}
