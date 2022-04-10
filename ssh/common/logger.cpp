
#include "logger.hpp"

#include <utility>
#include <stdio.h>

namespace securepath::ssh {

void stdout_logger::do_log_line(logger::type, std::string const& s, std::source_location&&) {
	std::puts(s.c_str());
}

session_logger::session_logger(logger& l, std::string tag)
: log_(l)
, tag_(std::move(tag))
{}

void session_logger::do_log_line(logger::type t, std::string const& s, std::source_location&& loc) {
	log_.log_line(t, tag_ + s, std::move(loc));
}

}
