#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

static int require_closed(int fd) {
    errno = 0;
    if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
        return 0;
    }
    fprintf(stderr, "descriptor %d unexpectedly survived exec\n", fd);
    return 1;
}

static int require_file_kind(int fd, mode_t kind) {
    struct stat info;
    if (fstat(fd, &info) == -1) {
        perror("fstat");
        return 1;
    }
    if ((info.st_mode & S_IFMT) != kind) {
        fprintf(stderr, "descriptor %d has unexpected file kind\n", fd);
        return 1;
    }
    return 0;
}

static int require_listener(int fd, int expected) {
    int accepting = 0;
    socklen_t size = sizeof(accepting);
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &size) == -1) {
        perror("getsockopt(SO_ACCEPTCONN)");
        return 1;
    }
    if (accepting != expected) {
        fprintf(stderr, "descriptor %d SO_ACCEPTCONN=%d, want %d\n", fd, accepting, expected);
        return 1;
    }
    return 0;
}

static int require_connected(int fd) {
    struct sockaddr_storage peer;
    socklen_t size = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &size) == -1) {
        perror("getpeername");
        return 1;
    }
    return 0;
}

int main(void) {
    const char *value = getenv("LANDRUN_EXPECT_PRESERVED");
    int preserved = value != NULL && value[0] == '1';

    if (!preserved) {
        int failed = 0;
        for (int fd = 3; fd <= 6; fd++) {
            failed |= require_closed(fd);
        }
        return failed;
    }

    if (require_file_kind(3, S_IFREG) || require_file_kind(4, S_IFDIR)) {
        return 1;
    }
    if (require_file_kind(5, S_IFSOCK) || require_listener(5, 1)) {
        return 1;
    }
    if (require_file_kind(6, S_IFSOCK) || require_listener(6, 0) || require_connected(6)) {
        return 1;
    }
    return 0;
}
