#ifndef SPSSH_CORE_SERVICE_HEADER_HEADER
#define SPSSH_CORE_SERVICE_HEADER_HEADER

#include "ssh/core/errors.hpp"
#include "ssh/core/packet_ser.hpp"
#include "ssh/core/packet_types.hpp"
#include "ssh/core/ssh_state.hpp"

namespace securepath::ssh {

class service_context {
public:

	//way to send packages
	//session id
	//crypto context
	//crypto call context (include log)

};

enum class service_state {
	none,
	inprogress,
	done,
	error
};

class ssh_service {
public:
	virtual ~ssh_service() = default;

	virtual std::string_view name() const = 0;
	virtual service_state state() const = 0;
	virtual handler_result process(ssh_packet_type, const_span payload) = 0;

	ssh_error_code error() const {
		return error_;
	}

	std::string error_message() const {
		return err_message_;
	}

protected:
	ssh_error_code error_{ssh_noerror};
	std::string err_message_;
};

}

#endif