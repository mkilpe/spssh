#ifndef SP_SHH_TYPES_HEADER
#define SP_SHH_TYPES_HEADER

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securepath::ssh {

using byte_vector = std::vector<std::byte>;
using span = std::span<std::byte>;
using const_span = std::span<std::byte const>;

// Represents multiple precision integers in two's complement format, 8 bits per byte, MSB first.
struct const_mpint_span {
	const_span data;
	enum sign_type { unsigned_t, signed_t } sign = unsigned_t;
};

struct ssh_version {
	std::string ssh;
	std::string software;
	std::string comment;
};

enum class transport_side {
	client,
	server
};

inline std::string_view to_string_view(const_span s) {
	return std::string_view((char const*)s.data(), s.size());
}

inline const_span to_span(std::string_view v) {
	return const_span((std::byte const*)v.data(), v.size());
}

inline std::uint8_t const* to_uint8_ptr(byte_vector const& v) {
	return (std::uint8_t const*)v.data();
}

inline std::uint8_t* to_uint8_ptr(byte_vector& v) {
	return (std::uint8_t*)v.data();
}

inline std::uint8_t const* to_uint8_ptr(const_span s) {
	return (std::uint8_t const*)s.data();
}

inline std::uint8_t* to_uint8_ptr(span s) {
	return (std::uint8_t*)s.data();
}

#if !defined(SPSSH_ASSERT) && !defined(NDEBUG)
#	define SPSSH_ASSERT(cond, message) assert((cond) && (message))
#endif

}

#endif
