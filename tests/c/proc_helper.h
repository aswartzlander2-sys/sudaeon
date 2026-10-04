/* Tiny fork/exec helper shared by the Sudaeon C tests. */
#ifndef SUDAEON_PROC_HELPER_H
#define SUDAEON_PROC_HELPER_H

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

/* Run argv with `input` on stdin, capturing stdout+stderr into out.
 * Returns the exit status (or -1 when the program could not be run). */
static int run_program(char *const argv[], const char *input, char *out, size_t outlen)
{
    int in_pipe[2], out_pipe[2];
    pid_t pid;
    size_t written = 0, used = 0;
    size_t length = input ? strlen(input) : 0;
    int status = 0;
    time_t started;

    if (out && outlen)
        out[0] = '\0';
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0)
        return -1;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        close(in_pipe[1]);
        close(out_pipe[0]);
        if (dup2(in_pipe[0], STDIN_FILENO) < 0)
            _exit(127);
        if (dup2(out_pipe[1], STDOUT_FILENO) < 0)
            _exit(127);
        if (dup2(out_pipe[1], STDERR_FILENO) < 0)
            _exit(127);
        close(in_pipe[0]);
        close(out_pipe[1]);
        execve(argv[0], argv, environ);
        _exit(127);
    }

    close(in_pipe[0]);
    close(out_pipe[1]);
    signal(SIGPIPE, SIG_IGN);
    while (written < length) {
        ssize_t got = write(in_pipe[1], input + written, length - written);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        written += (size_t)got;
    }
    close(in_pipe[1]);

    started = time(NULL);
    for (;;) {
        ssize_t got = read(out_pipe[0], (out ? out + used : NULL),
                           (out && used + 1 < outlen) ? outlen - used - 1 : 0);
        if (got > 0) {
            used += (size_t)got;
            if (out && used < outlen)
                out[used] = '\0';
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (got <= 0) {
            /* EOF or no buffer space: wait for the child, with a timeout */
            pid_t done = waitpid(pid, &status, WNOHANG);
            if (done == pid)
                break;
            if (done < 0)
                return -1;
            if (time(NULL) - started > 90) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                return -2;
            }
            if (!out || outlen == 0 || used + 1 >= outlen) {
                /* keep draining to avoid blocking the child */
                char sink[256];
                ssize_t drained = read(out_pipe[0], sink, sizeof(sink));
                (void)drained;
            }
            struct timespec pause = {0, 20 * 1000 * 1000};
            nanosleep(&pause, NULL);
        }
    }
    close(out_pipe[0]);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return -1;
}

#endif /* SUDAEON_PROC_HELPER_H */
