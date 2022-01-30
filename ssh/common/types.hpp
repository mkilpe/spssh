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

#define SPSSH_ASSERT(cond, message) assert((cond) && (#message))

}

#endif
