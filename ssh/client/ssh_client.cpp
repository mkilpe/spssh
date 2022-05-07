#include "ssh_client.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"

namespace securepath::ssh {

ssh_client::ssh_client(client_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: ssh_transport(conf, log, out, std::move(cc))
, config_(conf)
{
}

void ssh_client::on_state_change(ssh_state old_s, ssh_state new_s) {
	if(old_s == ssh_state::kex && new_s == ssh_state::transport) {
		// we are done with kex, request user auth
		send_packet<ser::service_request>(user_auth_service_name);
		requesting_auth_ = true;
	}
}

handler_result ssh_client::handle_kex_done(kex const& k) {
	/*
		check here if k->server_host_key() is key we allow and call the base class function if so.
		Otherwise set error and disconnect state. For async handling, return handler_result::pending
		in which case the function will get called again on next round of processing
	*/
	return ssh_transport::handle_kex_done(k);
}

handler_result ssh_client::handle_service_accept(const_span payload) {
	logger_.log(logger::debug_trace, "SSH handle_service_accept");

	ser::service_accept::load packet(payload);
	if(!packet) {
		set_error_and_disconnect(spssh_invalid_packet);
		logger_.log(logger::error, "SSH Invalid service accept packet from remote");
		return handler_result::handled;
	}

	auto& [service] = packet;

	if(state() == ssh_state::transport && requesting_auth_) {
		if(service == user_auth_service_name) {
			logger_.log(logger::debug_trace, "SSH user auth service accepted");
			start_user_auth();
		} else {
			set_error_and_disconnect(spssh_invalid_packet);
			logger_.log(logger::error, "SSH Received service accept in invalid state");
		}
		return handler_result::handled;
	}

	return handler_result::unknown;
}

handler_result ssh_client::handle_user_auth(ssh_packet_type type, const_span payload) {
	SPSSH_ASSERT(service_, "auth service not set");
	auto res = service_->process(type, payload);
	if(service_->error() != ssh_noerror) {
		set_error_and_disconnect(service_->error(), service_->error_message());
	}
	return res;
}


handler_result ssh_client::handle_service_packet(ssh_packet_type type, const_span payload) {
	return handler_result::handled;
}

handler_result ssh_client::handle_transport_packet(ssh_packet_type type, const_span payload) {
	if(type == ssh_service_accept) {
		return handle_service_accept(payload);
	} else if(type >= 51 && type < 80) { //accept only auth packets types from server
		if(state() != ssh_state::user_authentication) {
			set_error_and_disconnect(ssh_protocol_error);
			logger_.log(logger::error, "SSH Received packet in wrong state [type={}]", int(type));
			return handler_result::handled;
		}
		return handle_user_auth(type, payload);
	} else if(type >= 80) {
		if(state() != ssh_state::service) {
			set_error_and_disconnect(ssh_protocol_error);
			logger_.log(logger::error, "SSH Received packet in wrong state [type={}]", int(type));
			return handler_result::handled;
		}
		return handle_service_packet(type, payload);
	}

	return handler_result::unknown;
}

void ssh_client::start_user_auth() {
	set_state(ssh_state::user_authentication);
	service_ = construct_service(user_auth_service_name);
	if(!service_) {
		set_error_and_disconnect(ssh_service_not_available);
		logger_.log(logger::error, "Failed to construct required service");
	} else if(service_->error() != ssh_noerror) {
		set_error_and_disconnect(service_->error(), service_->error_message());
	} else {
		service_->init();
	}
}

std::unique_ptr<ssh_service> ssh_client::construct_service(std::string_view name) {
	if(name == user_auth_service_name) {
		return std::make_unique<default_client_auth>(*this, config_);
	}
	return nullptr;
}

}

