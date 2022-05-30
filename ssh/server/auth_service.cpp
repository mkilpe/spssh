#include "auth_service.hpp"

#include "ssh/core/auth/auth_protocol.hpp"
#include "ssh/core/packet_ser_impl.hpp"

#include <bit>

namespace securepath::ssh {

auth_bits auth_context::viable_methods() const {
	return (req.required | req.allowed) & ~successful;
}

static std::vector<std::string_view> to_method_list(auth_bits mask) {
	std::vector<std::string_view> list;
	for(auth_bits i = 1; i < auth_bits(auth_type::end_of_list); i *= 2) {
		if(mask & i) {
			list.push_back(to_string(auth_type(i)));
		}
	}
	return list;
}

std::vector<std::string_view> auth_context::viable_method_list() const {
	return to_method_list(viable_methods());
}

std::vector<std::string_view> auth_context::succeeded_method_list() const {
	return to_method_list(successful);
}

server_auth_service::server_auth_service(ssh_transport& transport, auth_config const& c)
: transport_(transport)
, auth_config_(c)
, log_(transport_.log())
, tries_left(c.num_of_tries)
{
}

std::string_view server_auth_service::name() const {
	return user_auth_service_name;
}

service_state server_auth_service::state() const {
	return state_;
}

bool server_auth_service::init() {
	if(!auth_config_.banner.empty()) {
		log_.log(logger::info, "sending banner '{}'", auth_config_.banner);
		transport_.send_packet<ser::userauth_banner>(auth_config_.banner, "");
	}
	return true;
}

auth_info server_auth_service::info_authenticated() const {
	return state_ == service_state::done ? auth_info{current_.service, current_.username} : auth_info{};
}

bool server_auth_service::update_current(std::string_view user, std::string_view service) {
	if(user.empty() || service.empty()) {
		return false;
	}

	if(user != current_.username || service != current_.service) {
		//username or service doesn't match, reset the current auth state
		auto it = auth_config_.service_auth.find(service);
		if(it == auth_config_.service_auth.end()) {
			log_.log(logger::error, "invalid service [username={}, service={}]", user, service);
			return false;
		}

		current_.req = it->second;
		current_.username = std::string(user);
		current_.service = std::string(service);
		current_.successful = 0;
	}

	return true;
}

void server_auth_service::handle_none_request() {
	if(current_.req.required == 0 && current_.req.num_req == 0) {
		// no auth needed, success
		log_.log(logger::info, "User authentication succeeded [methods=none]");
		transport_.send_packet<ser::userauth_success>();
		state_ = service_state::done;
		auth_succeeded(current_);
	} else {
		transport_.send_packet<ser::userauth_failure>(current_.viable_method_list(), false);
	}
}

void server_auth_service::handle_auth_success(auth_type succ) {
	current_.successful |= auth_bits(succ);
	bool has_required = (current_.req.required & current_.successful) == current_.req.required;
	bool has_num = std::popcount(current_.successful) >= current_.req.num_req;

	if(has_required && has_num) {
		log_.log(logger::info, "User authentication succeeded [methods={}]", to_string(current_.succeeded_method_list()));
		transport_.send_packet<ser::userauth_success>();
		state_ = service_state::done;
		auth_succeeded(current_);
	} else {
		log_.log(logger::info, "Partial authentication success [method={}]", to_string(succ));
		transport_.send_packet<ser::userauth_failure>(current_.viable_method_list(), true);
	}
}

void server_auth_service::handle_auth_failure(auth_type succ) {
	--tries_left;
	log_.log(logger::info, "Failed authentication [method={}, tries_left={}]", to_string(succ), tries_left);
	transport_.send_packet<ser::userauth_failure>(current_.viable_method_list(), false);
	if(tries_left == 0) {
		state_ = service_state::error;
		set_error(ssh_no_more_auth_methods_available, "Too many tries to authenticate");
	}
}

handler_result server_auth_service::handle_password_request(const_span payload) {
	if((current_.viable_methods() & auth_type::password) == 0) {
		handle_auth_failure(auth_type::password);
		return handler_result::handled;
	}

	ser::userauth_password_request::load packet(payload);
	if(!packet) {
		transport_.set_error_and_disconnect(ssh_protocol_error, "invalid userauth password request");
		return handler_result::handled;
	}

	auto& [user, service, method, is_change_pass, password] = packet;
	if(is_change_pass) {
		// we don't support password changing for now
		transport_.send_packet<ser::userauth_failure>(current_.viable_method_list(), false);
		return handler_result::handled;
	}

	// the user/service/method has already been checked earlier
	auto res = verify_password(current_, password);
	if(res == auth_state::pending) {
		return handler_result::pending;
	}

	if(res == auth_state::succeeded) {
		handle_auth_success(auth_type::password);
	} else {
		handle_auth_failure(auth_type::password);
	}

	return handler_result::handled;
}

handler_result server_auth_service::handle_pk_query(ssh_public_key const& key, std::string_view pk_blob) {
	auto res = verify_public_key(current_, key);
	if(res == auth_state::pending) {
		return handler_result::pending;
	}
	if(res == auth_state::succeeded) {
		transport_.send_packet<ser::userauth_pk_ok>(to_string(key.type()), pk_blob);
	} else {
		transport_.send_packet<ser::userauth_failure>(current_.viable_method_list(), false);
	}
	return handler_result::handled;
}

handler_result server_auth_service::handle_pk_auth(ssh_public_key const& key, const_span p_msg, const_span sig) {
	auto sid = transport_.session_id();

	// construct the data that is signed
	byte_vector msg;
	msg.reserve(4+sid.size() + 1 + p_msg.size());

	ssh_bf_writer w(msg);
	w.write(to_string_view(sid));
	w.write(ssh_userauth_request);
	w.write(p_msg);

	if(key.verify(msg, sig)) {
		auto res = verify_public_key(current_, key);
		if(res == auth_state::pending) {
			return handler_result::pending;
		}
		if(res == auth_state::succeeded) {
			handle_auth_success(auth_type::public_key);
		} else {
			log_.log(logger::error, "Public key not allowed");
			handle_auth_failure(auth_type::public_key);
		}
	} else {
		log_.log(logger::error, "Verifying signature failed");
		handle_auth_failure(auth_type::public_key);
	}
	return handler_result::handled;
}

handler_result server_auth_service::handle_pk_request(const_span payload) {
	if((current_.viable_methods() & auth_type::public_key) == 0) {
		handle_auth_failure(auth_type::public_key);
		return handler_result::handled;
	}

	ser::userauth_pk_request::load packet(payload);
	if(!packet) {
		transport_.set_error_and_disconnect(ssh_protocol_error, "invalid userauth pk request");
		return handler_result::handled;
	}

	auto& [user, service, method, is_auth, pk_alg, pk] = packet;
	auto key = load_ssh_public_key(to_span(pk), transport_.crypto(), transport_.call_context());
	if(!key.valid() || to_string(key.type()) != pk_alg) {
		log_.log(logger::debug, "invalid or unsupported public_key");
		handle_auth_failure(auth_type::public_key);
		return handler_result::handled;
	}

	if(is_auth) {
		// read the signature at the end of the packet
		std::string_view sig;
		if(!packet.reader().read(sig)) {
			transport_.set_error_and_disconnect(ssh_protocol_error, "invalid userauth pk request");
			return handler_result::handled;
		}
		return handle_pk_auth(key, safe_subspan(payload, 0, packet.size()), to_span(sig));
	} else {
		return handle_pk_query(key, pk);
	}
}

handler_result server_auth_service::handle_hostbased_request(const_span payload) {
	handle_auth_failure(auth_type::hostbased);
	return handler_result::handled;
}

handler_result server_auth_service::handle_interactive_request(const_span payload) {
	/*
		implementing this requires a state, ie. SSH_MSG_USERAUTH_INFO_REQUEST sent and waiting
		SSH_MSG_USERAUTH_INFO_RESPONSE. Receiving any other request meanwhile will reset this
		state
	*/
	handle_auth_failure(auth_type::interactive);
	return handler_result::handled;
}

handler_result server_auth_service::process(ssh_packet_type type, const_span payload) {
	if(type == ssh_userauth_request) {
		ser::userauth_request::load packet(payload);
		if(packet) {
			auto& [user, service, method] = packet;
			if(update_current(user, service)) {
				if(method == "none") {
					handle_none_request();
				} else if(method == "password") {
					return handle_password_request(payload);
				} else if(method == "publickey") {
					return handle_pk_request(payload);
				} else if(method == "hostbased") {
					return handle_hostbased_request(payload);
				} else if(method == "keyboard-interactive") {
					return handle_interactive_request(payload);
				} else {
					handle_auth_failure(auth_type::none);
				}
			} else {
				transport_.set_error_and_disconnect(ssh_service_not_available, "bad service");
			}
		}
		return handler_result::handled;
	}

	state_ = service_state::error;
	set_error(spssh_invalid_packet, "invalid packet");
	return handler_result::unknown;
}

}
