#ifndef SECUREPATH_TOOLS_COMMON_UTIL_HEADER
#define SECUREPATH_TOOLS_COMMON_UTIL_HEADER

#include "ssh/common/types.hpp"
#include "ssh/core/ssh_config.hpp"

namespace securepath::ssh {

byte_vector read_file(std::string const& file);

ssh_config test_tool_default_config();

std::string tokenise_command(std::string const& line, std::vector<std::string>& args);

/// print prompt and read a line from stdin; terminal echo is turned off when echo is false (for passwords)
std::string prompt_input(std::string const& prompt, bool echo);

class sync_cout_logger : public logger {
public:
	using logger::logger;

protected:
	void do_log_line(type, std::string const&, std::source_location&&) override;
};

}

#endif
