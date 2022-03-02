
#include "logger.hpp"

#include <stdio.h>

namespace securepath::ssh {

void stdout_logger::log_line(logger::type, std::string&& s, std::source_location&&) {
	std::puts(s.c_str());
}

}
