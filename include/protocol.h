#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define OTPE_VERSION     0x01
#define OTPE_HEADER_SIZE 16
#define OTPE_TOKEN_SIZE  8

typedef enum {
    OTPE_CMD_TCP     = 0x01,
    OTPE_CMD_UDP     = 0x02,
    OTPE_CMD_STREAM  = 0x03,
    OTPE_CMD_PING    = 0x10,
    OTPE_CMD_PONG    = 0x11,
    OTPE_CMD_CONNECT = 0x20
} otpe_command_t;

typedef struct {
    uint8_t  version;
    uint8_t  command;
    uint8_t  flags;
    uint8_t  reserved;
    uint16_t length;
    uint16_t checksum;
    uint8_t  token[OTPE_TOKEN_SIZE];
} otpe_header_t;

bool otpe_encode_header(const otpe_header_t* header, uint8_t* buffer, size_t buffer_size);
bool otpe_decode_header(const uint8_t* buffer, size_t buffer_size, otpe_header_t* header);
bool otpe_validate_header(const otpe_header_t* header);
uint16_t otpe_checksum(const uint8_t* buffer, size_t size);

#endif