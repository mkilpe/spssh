#include "service_handler.hpp"

#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"
#include "ssh/core/service/names.hpp"

namespace securepath::ssh {

service_handler::service_handler(ssh_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: ssh_transport(conf, log, out, std::move(cc))
{
}

void service_handler::init_service() {
	SPSSH_ASSERT(service_, "invalid state");
	if(!service_->init()) {
		logger_.log(logger::error, "Failed to initialise required service");
		set_error_and_disconnect(service_->error(), service_->error_message());
	}
}

void service_handler::start_service(auth_info const& info) {
	logger_.log(logger::info, "Starting service '{}' for user '{}'", info.service, info.user);
	service_ = construct_service(info);
	if(!service_) {
		set_error_and_disconnect(ssh_service_not_available);
		logger_.log(logger::error, "Failed to construct required service");
	} else if(service_->error() != ssh_noerror) {
		set_error_and_disconnect(service_->error(), service_->error_message());
	} else {
		init_service();
	}
}

void service_handler::start_user_auth() {
	service_ = construct_auth();
	if(!service_) {
		set_error_and_disconnect(ssh_service_not_available);
		logger_.log(logger::error, "Failed to construct required service");
	} else if(service_->error() != ssh_noerror) {
		set_error_and_disconnect(service_->error(), service_->error_message());
	} else {
		// if we are server, send the service accepted
		if(config().side == transport_side::server) {
			send_packet<ser::service_accept>(user_auth_service_name);
		}

		// initialise the service after sending the service accept in case it sends service specific packets
		init_service();
	}
}

std::unique_ptr<ssh_service> service_handler::construct_service(auth_info const& info) {
	if(info.service == connection_service_name) {
		return std::make_unique<ssh_connection>(*this);
	}
	return nullptr;
}

bool service_handler::flush() {
	return service_ ? service_->flush() : false;
}


}
