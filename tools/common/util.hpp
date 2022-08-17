#ifndef SECUREPATH_TOOLS_COMMON_UTIL_HEADER
#define SECUREPATH_TOOLS_COMMON_UTIL_HEADER

#include "ssh/common/types.hpp"
#include "ssh/core/ssh_config.hpp"

namespace securepath::ssh {

byte_vector read_file(std::string const& file);

ssh_config test_tool_default_config();

}

#endif
