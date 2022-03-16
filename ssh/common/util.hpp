#ifndef SP_SHH_UTIL_HEADER
#define SP_SHH_UTIL_HEADER

#include "types.hpp"
#include <cstring>

namespace securepath::ssh {

inline void copy(const_span source, span dest) {
	SPSSH_ASSERT(dest.size() >= source.size(), "invalid destination span for copy");
	SPSSH_ASSERT(!source.empty(), "invalid source span for copy");

	std::memcpy(dest.data(), source.data(), source.size());
}

}

#endif
