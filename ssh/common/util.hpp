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

}

#endif
