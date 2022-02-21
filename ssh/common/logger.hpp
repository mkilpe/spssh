#ifndef SP_SSH_LOGGER_HEADER
#define SP_SSH_LOGGER_HEADER

#include "types.hpp"

//not yet supported by gcc
//#include <format>
#include <source_location>

namespace securepath::ssh {

// very simple formatting to replace std::format until gcc supports it
template<typename... Args>
std::string my_simple_format(std::string_view fmt, Args const&...);

class logger {
public:
	enum type {
		info          = 0x1,
		error         = 0x2,
		debug         = 0x4,
		debug_trace   = 0x8,
		debug_verbose = 0x10,

		log_none = 0,
		log_all = info | error | debug | debug_trace | debug_verbose
	};

	virtual ~logger() = default;

	logger(logger const&) = delete;
	logger& operator=(logger const&) = delete;

	struct log_type {
		log_type(logger::type t, std::source_location location = std::source_location::current())
		: type(t)
		, location(std::move(location))
		{}

		logger::type type;
		std::source_location location;
	};

	template<typename... Args>
	void log(log_type t, std::string_view format, Args&&... args)
	{
		if(would_log(t.type)) {
			//todo: wait gcc to support std::format to enable this
			//log_line(t, std::format(fmt, std::forward<Args>(args)...), std::move(location));
			log_line(t.type, my_simple_format(format, std::forward<Args>(args)...), std::move(t.location));
		}
	}

	virtual void log_line(type, std::string&&, std::source_location&&) = 0;

	bool would_log(type t) const {
		return t & level_;
	}

private:
	type level_{log_all};
};

template<typename... Args>
std::string my_simple_format(std::string_view fmt, Args const&...) {
	//todo: implement
	return std::string(fmt);
}

}

#endif
