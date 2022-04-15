#include "ssh_client.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"

namespace securepath::ssh {

ssh_client::ssh_client(ssh_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: ssh_transport(conf, log, out, std::move(cc))
{
}

void ssh_client::on_state_change(ssh_state old_s, ssh_state new_s) {
	if(old_s == ssh_state::kex && new_s == ssh_state::transport) {
		// we are done with kex, request user auth
		send_packet<ser::service_request>(ser::user_auth_service_name);
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
		if(service == ser::user_auth_service_name) {
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

handler_result ssh_client::handle_transport_packet(ssh_packet_type type, const_span payload) {
	if(type == ssh_service_accept) {
		return handle_service_accept(payload);
	}

	return handler_result::unknown;
}

void ssh_client::start_user_auth() {
	//try first public key auth if any private keys set in config
	//then try password auth if failed or more auth is required
}

std::unique_ptr<ssh_service> ssh_client::construct_service(std::string_view name) {
	if(name == ser::user_auth_service_name) {
		return std::make_unique<client_auth_service>();
	}
	return nullptr;
}

}

