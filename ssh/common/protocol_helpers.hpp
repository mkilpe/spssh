#ifndef SP_SHH_PROTOCOL_HELPERS_HEADER
#define SP_SHH_PROTOCOL_HELPERS_HEADER

#include "types.hpp"
#include "buffers.hpp"

namespace securepath::ssh {

bool send_version_string(ssh_version const& version, out_buffer&);

enum class version_parse_result {
	ok,
	more_data,
	error
};

version_parse_result parse_ssh_version(in_buffer&, bool allow_non_version_lines, ssh_version& version);

}

#endif
