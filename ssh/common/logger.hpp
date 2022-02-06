#ifndef SP_SSH_LOGGER_HEADER
#define SP_SSH_LOGGER_HEADER

#include "types.hpp"

#include <format>
#include <source_location>

namespace securepath::ssh {

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

	template<typename... Args>
	void log(type t, std::string_view fmt, Args&&... args
		, std::source_location location = std::source_location::current())
	{
		if(would_log(t)) {
			log_line(t, std::format(fmt, std::forward<Args>(args)...), std::move(location));
		}
	}

	virtual void log_line(type, std::string&&, std::source_location&&) = 0;

	bool would_log(type t) const {
		return t & level_;
	}

private:
	type level_{log_all};
};

}

#endif
