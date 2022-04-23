#include "ssh_server.hpp"

#include "ssh/core/protocol.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/service/names.hpp"

namespace securepath::ssh {

ssh_server::ssh_server(ssh_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: ssh_transport(conf, log, out, std::move(cc))
{
}

void ssh_server::handle_service_request(const_span payload) {
	ser::service_request::load packet(payload);
	if(packet) {
		auto& [service] = packet;
		// we only allow user auth at this point
		if(service != user_auth_service_name) {
			set_error_and_disconnect(ssh_service_not_available);
			return;
		}

		start_user_auth();

	} else {
		logger_.log(logger::error, "Received invalid service request packet");
		set_error_and_disconnect(spssh_invalid_packet);
	}
}

handler_result ssh_server::handle_transport_packet(ssh_packet_type type, const_span payload) {
	if(type == ssh_service_request) {
		handle_service_request(payload);
	} else {
		return handler_result::unknown;
	}
	return handler_result::handled;
}

void ssh_server::start_user_auth() {
	service_ = construct_service(user_auth_service_name);
	if(!service_) {
		set_error_and_disconnect(ssh_service_not_available);
		logger_.log(logger::error, "Failed to construct required service");
	} else if(service_->error() != ssh_noerror) {
		set_error_and_disconnect(service_->error(), service_->error_message());
	} else {
		set_state(ssh_state::user_authentication);
		send_packet<ser::service_accept>(user_auth_service_name);
	}
}

}
