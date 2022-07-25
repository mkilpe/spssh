#include "ssh_server.hpp"

#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"
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

void ssh_server::start_service(auth_info const& info) {
	logger_.log(logger::info, "Starting service '{}' for user '{}'", info.service, info.user);
	service_ = construct_service(info);
	if(!service_) {
		set_error_and_disconnect(ssh_service_not_available);
		logger_.log(logger::error, "Failed to construct required service");
	} else if(service_->error() != ssh_noerror) {
		set_error_and_disconnect(service_->error(), service_->error_message());
	} else {
		set_state(ssh_state::service);

		// initialise the service after sending the service accept in case it sends service specific packets
		if(!service_->init()) {
			set_error_and_disconnect(service_->error(), service_->error_message());
		}
	}
}

handler_result ssh_server::process_service(ssh_packet_type type, const_span payload) {
	SPSSH_ASSERT(service_, "no service set");
	auto res = service_->process(type, payload);
	if(res == handler_result::handled) {
		// see if the service is done
		auto s_state = service_->state();
		if(s_state == service_state::done) {
			if(state() == ssh_state::user_authentication) {
				auth_service& auth = static_cast<auth_service&>(*service_);
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

void ssh_server::start_user_auth() {
	service_ = construct_auth();
	if(!service_) {
		set_error_and_disconnect(ssh_service_not_available);
		logger_.log(logger::error, "Failed to construct required service");
	} else if(service_->error() != ssh_noerror) {
		set_error_and_disconnect(service_->error(), service_->error_message());
	} else {
		set_state(ssh_state::user_authentication);
		send_packet<ser::service_accept>(user_auth_service_name);

		// initialise the service after sending the service accept in case it sends service specific packets
		if(!service_->init()) {
			set_error_and_disconnect(service_->error(), service_->error_message());
		}
	}
}

std::unique_ptr<ssh_service> ssh_server::construct_service(auth_info const& info) {
	if(info.service == connection_service_name) {
		return std::make_unique<ssh_connection>(*this);
	}
	return nullptr;
}

bool ssh_server::flush() {
	return service_ ? service_->flush() : false;
}


}
