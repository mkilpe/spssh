#include "ssh_server.hpp"

#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"
#include "ssh/core/service/names.hpp"

namespace securepath::ssh {

ssh_server::ssh_server(ssh_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: service_handler(conf, log, out, std::move(cc))
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

		requesting_auth_ = true;
		start_user_auth();

	} else {
		logger_.log(logger::error, "Received invalid service request packet");
		set_error_and_disconnect(spssh_invalid_packet);
	}
}

handler_result ssh_server::process_service(ssh_packet_type type, const_span payload) {
	SPSSH_ASSERT(service_, "no service set");
	auto res = service_->process(type, payload);
	if(res == handler_result::handled) {
		// see if the service is done
		auto s_state = service_->state();
		if(s_state == service_state::done) {
			if(requesting_auth_) {
				auth_service& auth = static_cast<auth_service&>(*service_);
				requesting_auth_ = false;
				user_authenticated_ = true;
				//get the service we authenticated for and start it
				start_service(auth.info_authenticated());
			} else {
				//service done? what now, lets just disconnect
				logger_.log(logger::info, "Service '{}' completed, disconnecting...", service_->name());
				disconnect();
			}
		} else if(s_state == service_state::error) {
			logger_.log(logger::info, "Service error, disconnecting...");
			set_error_and_disconnect(service_->error(), service_->error_message());
		}
	}
	return res;
}

handler_result ssh_server::handle_transport_packet(ssh_packet_type type, const_span payload) {
	if(type == ssh_service_request) {
		handle_service_request(payload);
		return handler_result::handled;
	} else if(service_) {
		return process_service(type, payload);
	}
	return handler_result::unknown;
}

}
