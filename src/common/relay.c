#include "relay.h"
#include "dns_cache.h"
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define RELAY_IDLE_TIMEOUT_MS 10000
#define RELAY_GRACE_TIMEOUT_MS 5000

int otpe_set_tcp_nodelay(int fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

static long elapsed_ms_since(struct timespec* start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000 +
           (now.tv_nsec - start->tv_nsec) / 1000000;
}

long otpe_relay_bidirectional(int fd_a, int fd_b) {
    struct pollfd fds[2];
    unsigned char buf[65536];
    long total = 0;
    int a_closed = 0, b_closed = 0;
    struct timespec last_activity;
    struct timespec grace_start = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &last_activity);

    while (!a_closed || !b_closed) {
        fds[0].fd = fd_a;
        fds[0].events = a_closed ? 0 : POLLIN;
        fds[1].fd = fd_b;
        fds[1].events = b_closed ? 0 : POLLIN;

        int timeout_ms;
        if (a_closed || b_closed) {
            if (grace_start.tv_sec == 0) clock_gettime(CLOCK_MONOTONIC, &grace_start);
            long elapsed = elapsed_ms_since(&grace_start);
            if (elapsed >= RELAY_GRACE_TIMEOUT_MS) break;
            timeout_ms = RELAY_GRACE_TIMEOUT_MS - (int)elapsed;
        } else {
            long idle = elapsed_ms_since(&last_activity);
            if (idle >= RELAY_IDLE_TIMEOUT_MS) {
                fprintf(stderr, "[relay] idle timeout (%ld ms no data)\n", idle);
                break;
            }
            timeout_ms = RELAY_IDLE_TIMEOUT_MS - (int)idle;
        }

        int ready = poll(fds, 2, timeout_ms);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) continue;

        if (!a_closed && (fds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(fd_a, buf, sizeof(buf), 0);
            if (n <= 0) {
                a_closed = 1;
                shutdown(fd_b, SHUT_WR);
            } else {
                clock_gettime(CLOCK_MONOTONIC, &last_activity);
                ssize_t sent = 0;
                while (sent < n) {
                    ssize_t w = send(fd_b, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
                    if (w <= 0) { a_closed = 1; b_closed = 1; break; }
                    sent += w;
                }
                total += n;
            }
        }

        if (!b_closed && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(fd_b, buf, sizeof(buf), 0);
            if (n <= 0) {
                b_closed = 1;
                shutdown(fd_a, SHUT_WR);
            } else {
                clock_gettime(CLOCK_MONOTONIC, &last_activity);
                ssize_t sent = 0;
                while (sent < n) {
                    ssize_t w = send(fd_a, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
                    if (w <= 0) { a_closed = 1; b_closed = 1; break; }
                    sent += w;
                }
                total += n;
            }
        }
    }
    return total;
}

long otpe_relay_tls_bidirectional(otpe_tls_t* tls, int raw_fd) {
    int tls_fd = otpe_tls_get_fd(tls);
    if (tls_fd < 0) return -1;

    unsigned char buf[65536];
    long total = 0;
    int tls_closed = 0, raw_closed = 0;
    struct timespec last_activity;
    struct timespec grace_start = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &last_activity);

    while (!tls_closed || !raw_closed) {
        struct pollfd fds[2];
        fds[0].fd = tls_fd;
        fds[0].events = (tls_closed || otpe_tls_pending(tls) > 0) ? 0 : POLLIN;
        fds[1].fd = raw_fd;
        fds[1].events = raw_closed ? 0 : POLLIN;

        int timeout_ms;
        if (tls_closed || raw_closed) {
            if (grace_start.tv_sec == 0) clock_gettime(CLOCK_MONOTONIC, &grace_start);
            long elapsed = elapsed_ms_since(&grace_start);
            if (elapsed >= RELAY_GRACE_TIMEOUT_MS) break;
            timeout_ms = RELAY_GRACE_TIMEOUT_MS - (int)elapsed;
        } else {
            long idle = elapsed_ms_since(&last_activity);
            if (idle >= RELAY_IDLE_TIMEOUT_MS) {
                fprintf(stderr, "[relay] idle timeout (%ld ms no data)\n", idle);
                break;
            }
            timeout_ms = RELAY_IDLE_TIMEOUT_MS - (int)idle;
        }

        int ready = poll(fds, 2, timeout_ms);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) continue;

        if (!tls_closed && (otpe_tls_pending(tls) > 0 || (fds[0].revents & (POLLIN | POLLHUP | POLLERR)))) {
            ssize_t n = otpe_tls_recv(tls, buf, sizeof(buf));
            if (n <= 0) {
                tls_closed = 1;
                shutdown(raw_fd, SHUT_WR);
            } else {
                clock_gettime(CLOCK_MONOTONIC, &last_activity);
                ssize_t sent = 0;
                while (sent < n) {
                    ssize_t w = send(raw_fd, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
                    if (w <= 0) { tls_closed = 1; raw_closed = 1; break; }
                    sent += w;
                }
                total += n;
            }
        }

        if (!raw_closed && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(raw_fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                raw_closed = 1;
            } else {
                clock_gettime(CLOCK_MONOTONIC, &last_activity);
                ssize_t sent = 0;
                while (sent < n) {
                    ssize_t w = otpe_tls_send(tls, buf + sent, (size_t)(n - sent));
                    if (w <= 0) { tls_closed = 1; raw_closed = 1; break; }
                    sent += w;
                }
                total += n;
            }
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

int otpe_connect_timeout(const char* host, uint16_t port) {
    struct addrinfo* res = dns_cache_lookup(host, port, SOCK_STREAM);
    if (!res) return -1;

    int fd = -1;
    int v6_timeout = 300;

    for (struct addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        fd = try_connect_one(p, 500);
        if (fd >= 0) return fd;
    }

    for (struct addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET6) continue;
        fd = try_connect_one(p, v6_timeout);
        if (fd >= 0) break;
    }

    return fd;
}