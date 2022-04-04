#ifndef SP_SHH_UTIL_HEADER
#define SP_SHH_UTIL_HEADER

#include "types.hpp"

#include <cstring>
#include <string_view>
#include <vector>

namespace securepath::ssh {

inline void copy(const_span source, span dest) {
	SPSSH_ASSERT(dest.size() >= source.size(), "invalid destination span for copy");
	SPSSH_ASSERT(!source.empty(), "invalid source span for copy");

	std::memcpy(dest.data(), source.data(), source.size());
}

std::vector<std::byte> decode_base64(std::string_view);

inline void u32ton(std::uint32_t v, std::byte* out) {
	out[0] = std::byte((v >> 24) & 0xff);
	out[1] = std::byte((v >> 16) & 0xff);
	out[2] = std::byte((v >> 8) & 0xff);
	out[3] = std::byte(v & 0xff);
}

inline std::uint32_t ntou32(std::byte const* in) {
	return (std::to_integer<std::uint32_t>(in[0]) << 24)
		| (std::to_integer<std::uint32_t>(in[1]) << 16)
		| (std::to_integer<std::uint32_t>(in[2]) << 8)
		| (std::to_integer<std::uint32_t>(in[3]));
}

inline void u64ton(std::uint64_t v, std::byte* out) {
	out[0] = std::byte((v >> 56) & 0xff);
	out[1] = std::byte((v >> 48) & 0xff);
	out[2] = std::byte((v >> 40) & 0xff);
	out[3] = std::byte((v >> 32) & 0xff);
	out[4] = std::byte((v >> 24) & 0xff);
	out[5] = std::byte((v >> 16) & 0xff);
	out[6] = std::byte((v >> 8) & 0xff);
	out[7] = std::byte(v & 0xff);
}

inline std::uint64_t ntou64(std::byte const* in) {
	return
		  (std::to_integer<std::uint64_t>(in[0]) << 56)
		| (std::to_integer<std::uint64_t>(in[1]) << 48)
		| (std::to_integer<std::uint64_t>(in[2]) << 40)
		| (std::to_integer<std::uint64_t>(in[3]) << 32)
		| (std::to_integer<std::uint64_t>(in[4]) << 24)
		| (std::to_integer<std::uint64_t>(in[5]) << 16)
		| (std::to_integer<std::uint64_t>(in[6]) << 8)
		| (std::to_integer<std::uint64_t>(in[7]));
}

// as per rfc4251 the unsigned mpint has trailing 0 byte, this removes that if present
inline const_span trim_umpint(const_span mpint) {
	if(!mpint.empty() && mpint[0] == std::byte{0x0}) {
		return mpint.subspan(1);
	}
	return mpint;
}

}

#endif
