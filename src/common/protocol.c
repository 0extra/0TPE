#include "protocol.h"
#include <string.h>

static uint16_t read_uint16_be(const uint8_t* buffer) {
    return (uint16_t)((buffer[0] << 8) | buffer[1]);
}

static void write_uint16_be(uint8_t* buffer, uint16_t value) {
    buffer[0] = (uint8_t)((value >> 8) & 0xFF);
    buffer[1] = (uint8_t)(value & 0xFF);
}

uint16_t otpe_checksum(const uint8_t* buffer, size_t size) {
    uint16_t sum = 0xFFFF;
    for (size_t i = 0; i < size; i++) {
        sum ^= buffer[i];
        sum = (uint16_t)((sum << 1) | (sum >> 15));
    }
    return sum;
}

bool otpe_encode_header(const otpe_header_t* header, uint8_t* buffer, size_t buffer_size) {
    if (buffer_size < OTPE_HEADER_SIZE) return false;

    buffer[0] = header->version;
    buffer[1] = header->command;
    buffer[2] = header->flags;
    buffer[3] = header->reserved;
    write_uint16_be(&buffer[4], header->length);
    write_uint16_be(&buffer[6], 0);
    memcpy(&buffer[8], header->token, OTPE_TOKEN_SIZE);

    uint16_t sum = otpe_checksum(buffer, OTPE_HEADER_SIZE);
    write_uint16_be(&buffer[6], sum);
    return true;
}

bool otpe_decode_header(const uint8_t* buffer, size_t buffer_size, otpe_header_t* header) {
    if (buffer_size < OTPE_HEADER_SIZE) return false;

    header->version  = buffer[0];
    header->command  = buffer[1];
    header->flags    = buffer[2];
    header->reserved = buffer[3];
    header->length   = read_uint16_be(&buffer[4]);
    header->checksum = read_uint16_be(&buffer[6]);
    memcpy(header->token, &buffer[8], OTPE_TOKEN_SIZE);

    uint8_t tmp[OTPE_HEADER_SIZE];
    memcpy(tmp, buffer, OTPE_HEADER_SIZE);
    tmp[6] = 0;
    tmp[7] = 0;
    uint16_t computed = otpe_checksum(tmp, OTPE_HEADER_SIZE);
    if (computed != header->checksum) return false;
    return true;
}

bool otpe_validate_header(const otpe_header_t* header) {
    if (header->version != OTPE_VERSION) return false;
    if (header->reserved != 0) return false;
    if (header->flags != 0) return false;
    switch (header->command) {
        case OTPE_CMD_TCP:
        case OTPE_CMD_UDP:
        case OTPE_CMD_STREAM:
        case OTPE_CMD_PING:
        case OTPE_CMD_PONG:
        case OTPE_CMD_CONNECT:
            break;
        default:
            return false;
    }
    if (header->command == OTPE_CMD_PING || header->command == OTPE_CMD_PONG) {
        if (header->length != 0) return false;
    }
    if (header->command == OTPE_CMD_CONNECT) {
        if (header->length < 2) return false;
    }
    return true;
}