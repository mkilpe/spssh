#include "ssh_client.hpp"
#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"
#include "ssh/core/service/names.hpp"

namespace securepath::ssh {

ssh_client::ssh_client(client_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: service_handler(conf, log, out, std::move(cc))
, config_(conf)
{
}

void ssh_client::on_state_change(ssh_state old_s, ssh_state new_s) {
	if(old_s == ssh_state::kex && new_s == ssh_state::transport) {
		// we are done with kex, request user auth unless we are already authenticated (rekeying)
		if(!user_authenticated_) {
			send_packet<ser::service_request>(user_auth_service_name);
			requesting_auth_ = true;
		}
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

	if(state() == ssh_state::transport && requesting_auth_) {
		auto& [service] = packet;

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

handler_result ssh_client::process_service(ssh_packet_type type, const_span payload) {
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

handler_result ssh_client::handle_transport_packet(ssh_packet_type type, const_span payload) {
	if(type == ssh_service_accept) {
		return handle_service_accept(payload);
	} else if(type >= 51 && type < 80) { //accept only auth packets types from server
		if(!requesting_auth_) {
			set_error_and_disconnect(ssh_protocol_error);
			logger_.log(logger::error, "SSH Received packet in wrong state [type={}]", int(type));
			return handler_result::handled;
		}
		return process_service(type, payload);
	} else if(type >= 80) {
		if(!user_authenticated_) {
			set_error_and_disconnect(ssh_protocol_error);
			logger_.log(logger::error, "SSH Received packet in wrong state [type={}]", int(type));
			return handler_result::handled;
		}
		return process_service(type, payload);
	}

	return handler_result::unknown;
}

std::unique_ptr<auth_service> ssh_client::construct_auth() {
	return std::make_unique<default_client_auth>(*this, config_);
}

}

