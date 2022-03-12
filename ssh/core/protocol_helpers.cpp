#include "protocol_helpers.hpp"

namespace securepath::ssh {

// form: "SSH-2.0-softwareversion comments CR LF"
bool send_version_string(ssh_version const& version, out_buffer& out) {
	std::string str = "SSH-" + version.ssh + "-" + version.software;
	if(!version.comment.empty()) {
		str += " ";
		str += version.comment;
	}
	str += "\r\n";
	return out.write(str);
}

// US ascii is-printable
// can't use std::isprint because it is locale dependent
static bool is_valid_version_char(char c) {
	return c >= 0x21 && c <= 0x2f
		|| c >= 0x30 && c <= 0x7e;
}

static bool is_valid_version_string(std::string_view str) {
	for(auto c : str) {
		if(!is_valid_version_char(c)) {
			return false;
		}
	}
	return true;
}


// maximum length of line including the ending Carriage Return and Line Feed (RFC 4253:4.2)
std::size_t const max_line_lenght = 255;

static version_parse_result parse_ssh_version_substrings(std::string_view str, ssh_version& version) {
	std::string_view ssh_v = str.substr(0, str.find("-"));

	//empty version number or no hyphen found
	if(ssh_v.empty() || ssh_v.size() == str.size()) {
		return version_parse_result::error;
	}

	if(!is_valid_version_string(ssh_v)) {
		return version_parse_result::error;
	}

	auto comment_p = str.find(" ");
	std::string_view soft_v = str.substr(ssh_v.size()+1, comment_p-ssh_v.size()-1);

	if(!is_valid_version_string(soft_v)) {
		return version_parse_result::error;
	}

	if(comment_p != std::string_view::npos) {
		version.comment = str.substr(comment_p+1);
	}
	version.ssh = ssh_v;
	version.software = soft_v;

	return version_parse_result::ok;
}

version_parse_result parse_ssh_version(in_buffer& in, bool allow_non_version_lines, ssh_version& version) {
	version_parse_result result = version_parse_result::more_data;
	const_span buf = in.get();
	if(!buf.empty()) {
		std::string_view str{reinterpret_cast<char const*>(buf.data()), buf.size()};
		if(allow_non_version_lines) {
			// ignore non "SSH-" starting lines
			while(!str.starts_with("SSH-")) {
				auto p = str.find("\r\n");
				if(p == std::string_view::npos) {
					return version_parse_result::more_data;
				}
				str = str.substr(p+2);
				in.consume(p+2);
			}
		}
		if(!str.starts_with("SSH-")) {
			return version_parse_result::error;
		}
		// cap the length
		str = str.substr(0, max_line_lenght);

		auto p = str.find("\r\n");
		if(p == std::string_view::npos) {
			return str.size() == max_line_lenght
				? version_parse_result::error : version_parse_result::more_data;
		}

		result = parse_ssh_version_substrings(str.substr(4, p-4), version);
		if(result == version_parse_result::ok) {
			in.consume(p+2);
		}
	}
	return result;
}

bool parse_string_list(std::string_view view, std::vector<std::string_view>& out) {
	std::string_view::size_type start = 0, end = 0;

	if(!view.empty()) {
		while(end != std::string_view::npos) {
			end = view.find_first_of(',', start);
			if(end == std::string_view::npos) {
				out.emplace_back(view.substr(start));
			} else {
				out.emplace_back(view.substr(start, end-start));
			}
			start = end + 1;
		}
	}

	return true;
}

bool to_string_list(std::vector<std::string_view> const& in, std::string& out) {
	bool first = true;
	for(auto&& v : in) {
		if(v.empty()) return false;
		if(v.find(',') != std::string_view::npos) return false;
		if(!first) out += ",";

		first = false;
		out += v;
	}
	return true;
}

}

