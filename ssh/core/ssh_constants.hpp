#ifndef SP_SHH_CONSTANTS_HEADER
#define SP_SHH_CONSTANTS_HEADER

#include <cstdint>

namespace securepath::ssh {

std::size_t constexpr packet_lenght_size = 4;
std::size_t constexpr padding_size = 1;
// header size = packet_length 4 bytes + padding length 1 byte
std::size_t constexpr packet_header_size = packet_lenght_size + padding_size;
std::size_t constexpr maximum_padding_size = 255;

// minimum "block" size, the length of header+payload must be multiple of the "block" size (even for stream ciphers).
std::size_t constexpr minimum_block_size = 8;

// at least 4 bytes of padding is always required per SSH specification
std::size_t constexpr minimum_padding_size = 4;

// size of the kex init cookie
std::size_t constexpr cookie_size = 16;

}

#endif
