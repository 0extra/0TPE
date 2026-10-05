#include "relay.h"
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int otpe_set_tcp_nodelay(int fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

long otpe_relay_bidirectional(int fd_a, int fd_b) {
    struct pollfd fds[2];
    fds[0].fd = fd_a;
    fds[0].events = POLLIN;
    fds[1].fd = fd_b;
    fds[1].events = POLLIN;

    unsigned char buf[65536];
    long total = 0;

    for (;;) {
        int ready = poll(fds, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) continue;

        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = recv(fd_a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            ssize_t sent = 0;
            while (sent < n) {
                ssize_t w = send(fd_b, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
                if (w <= 0) return -1;
                sent += w;
            }
            total += n;
        }

        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = recv(fd_b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            ssize_t sent = 0;
            while (sent < n) {
                ssize_t w = send(fd_a, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
                if (w <= 0) return -1;
                sent += w;
            }
            total += n;
        }
    }
    return total;
}

long otpe_relay_tls_bidirectional(otpe_tls_t* tls, int raw_fd) {
    int tls_fd = otpe_tls_get_fd(tls);
    if (tls_fd < 0) return -1;

    unsigned char buf[65536];
    long total = 0;

    for (;;) {
        struct pollfd fds[2];
        fds[0].fd = tls_fd;
        fds[0].events = otpe_tls_pending(tls) > 0 ? 0 : POLLIN;
        fds[1].fd = raw_fd;
        fds[1].events = POLLIN;

        int ready = poll(fds, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) continue;

        if (otpe_tls_pending(tls) > 0 || (fds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = otpe_tls_recv(tls, buf, sizeof(buf));
            if (n <= 0) break;
            ssize_t sent = 0;
            while (sent < n) {
                ssize_t w = send(raw_fd, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
                if (w <= 0) return -1;
                sent += w;
            }
            total += n;
        }

        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = recv(raw_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            ssize_t sent = 0;
            while (sent < n) {
                ssize_t w = otpe_tls_send(tls, buf + sent, (size_t)(n - sent));
                if (w <= 0) return -1;
                sent += w;
            }
            total += n;
        }
    }
    return total;
}

static int try_connect_one(struct addrinfo* p, int timeout_ms) {
    int fd = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol);
    if (fd < 0) return -1;

    int r = connect(fd, p->ai_addr, p->ai_addrlen);
    if (r == 0) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    r = poll(&pfd, 1, timeout_ms);
    if (r <= 0) {
        close(fd);
        return -1;
    }

    int err = 0;
    socklen_t errlen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    return fd;
}

int otpe_connect_timeout(const char* host, uint16_t port, int timeout_ms) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo* res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int fd = -1;
    int v6_timeout = timeout_ms < 2000 ? timeout_ms : 2000;

    for (struct addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        fd = try_connect_one(p, timeout_ms);
        if (fd >= 0) break;
    }

    if (fd < 0) {
        for (struct addrinfo* p = res; p; p = p->ai_next) {
            if (p->ai_family != AF_INET6) continue;
            fd = try_connect_one(p, v6_timeout);
            if (fd >= 0) break;
        }
    }

    freeaddrinfo(res);
    return fd;
}