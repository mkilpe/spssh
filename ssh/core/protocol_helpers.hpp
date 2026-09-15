#ifndef SP_SHH_PROTOCOL_HELPERS_HEADER
#define SP_SHH_PROTOCOL_HELPERS_HEADER

#include "ssh/common/types.hpp"
#include "ssh/common/buffers.hpp"

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

/// true if the string is a valid name for a name-list (rfc 4251 sections 5 and 6): non-empty printable US-ASCII
/// without whitespace, control characters, DEL or the list separator comma
bool is_valid_name(std::string_view name);

/// parses a name-list, fails if any of the names is not valid
bool parse_string_list(std::string_view, std::vector<std::string_view>& out);
/// serialises a name-list, fails if any of the names is not valid
bool to_string_list(std::vector<std::string_view> const& in, std::string& out);

}

#endif
