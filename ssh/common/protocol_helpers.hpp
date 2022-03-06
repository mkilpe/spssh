#ifndef SP_SHH_PROTOCOL_HELPERS_HEADER
#define SP_SHH_PROTOCOL_HELPERS_HEADER

#include "types.hpp"
#include "buffers.hpp"

#include <string_view>
#include <vector>

namespace securepath::ssh {

bool send_version_string(ssh_version const& version, out_buffer&);

enum class version_parse_result {
	ok,
	more_data,
	error
};

version_parse_result parse_ssh_version(in_buffer&, bool allow_non_version_lines, ssh_version& version);

bool parse_string_list(std::string_view, std::vector<std::string_view>& out);
bool to_string_list(std::vector<std::string_view> const& in, std::string& out);

}

#endif
