#ifndef SPSSH_CORE_SERVICE_HEADER
#define SPSSH_CORE_SERVICE_HEADER

#include "ssh/core/errors.hpp"
#include "ssh/core/packet_ser.hpp"
#include "ssh/core/packet_types.hpp"
#include "ssh/core/ssh_state.hpp"

namespace securepath::ssh {

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

	// called after constructing the service, returns true on success (this function can send packets specific to the service)
	virtual bool init() = 0;

	// flush buffers if possible, returns true if more data left to be flushed. Default impl does nothing.
	virtual bool flush() { return false; }

	// process a packet from network
	virtual handler_result process(ssh_packet_type, const_span payload) = 0;

	ssh_error_code error() const {
		return error_;
	}

	std::string error_message() const {
		return err_message_;
	}

	void set_error(ssh_error_code err, std::string msg) {
		error_ = err;
		err_message_ = std::move(msg);
	}

protected:
	ssh_error_code error_{ssh_noerror};
	std::string err_message_;
};

struct auth_info {
	std::string service;
	std::string user;
};

class auth_service : public ssh_service {
public:
	// service and user that was authenticated
	virtual auth_info info_authenticated() const = 0;
};

}

#endif
