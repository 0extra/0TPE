#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>
#include <stddef.h>

int socks5_handshake(int fd, uint8_t* cmd_out, char* out_host, size_t host_size,
                     uint16_t* out_port, uint16_t udp_listen_port);

#endif