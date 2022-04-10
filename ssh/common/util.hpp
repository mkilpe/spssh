#ifndef SP_SHH_UTIL_HEADER
#define SP_SHH_UTIL_HEADER

#include "types.hpp"

#include <cstring>
#include <string_view>
#include <vector>
#include <iosfwd>

namespace securepath::ssh {

inline void copy(const_span source, span dest) {
	SPSSH_ASSERT(dest.size() >= source.size(), "invalid destination span for copy");
	SPSSH_ASSERT(!source.empty(), "invalid source span for copy");

	std::memcpy(dest.data(), source.data(), source.size());
}

byte_vector decode_base64(std::string_view);
std::string encode_base64(const_span, bool pad = false);

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
inline const_mpint_span to_umpint(const_span mpint) {
	// remove the trailing zeroes
	while(!mpint.empty() && mpint[0] == std::byte{0x0}) {
		mpint = mpint.subspan(1);
	}
	return const_mpint_span{mpint};
}

inline const_mpint_span to_umpint(std::string_view mpint) {
	return to_umpint(to_span(mpint));
}

template<class T> concept Byte = std::is_same_v<std::remove_cv_t<T>, std::byte>;

/// std::span doesn't clamp the count to the size-offset which is what we want
template<Byte T>
inline std::span<T> safe_subspan(std::span<T> s, std::size_t offset, std::size_t count = std::dynamic_extent) {
	if(offset >= s.size()) {
		return {};
	}
	if(count != std::dynamic_extent) {
		count = std::min(count, s.size()-offset);
	}
	return s.subspan(offset, count);
}

inline span safe_subspan(byte_vector& s, std::size_t offset, std::size_t count = std::dynamic_extent) {
	return safe_subspan(span(s), offset, count);
}

inline const_span safe_subspan(byte_vector const& s, std::size_t offset, std::size_t count = std::dynamic_extent) {
	return safe_subspan(const_span(s), offset, count);
}

std::ostream& operator<<(std::ostream&, const_span);

bool same_source_or_non_overlapping(const_span s1, const_span s2);

}

#endif
