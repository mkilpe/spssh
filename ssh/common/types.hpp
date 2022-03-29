#ifndef SP_SHH_TYPES_HEADER
#define SP_SHH_TYPES_HEADER

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace securepath::ssh {

using span = std::span<std::byte>;
using const_span = std::span<std::byte const>;

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

#if !defined(SPSSH_ASSERT) && !defined(NDEBUG)
#	define SPSSH_ASSERT(cond, message) assert((cond) && (message))
#endif

}

#endif
