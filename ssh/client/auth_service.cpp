
#include "auth_service.hpp"
#include "ssh/core/auth/auth_protocol.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"
#include "ssh/core/ssh_transport.hpp"

namespace securepath::ssh {

client_auth_service::client_auth_service(ssh_transport& transport)
: transport_(transport)
, log_(transport_.log())
{
}

std::string_view client_auth_service::name() const {
	return user_auth_service_name;
}

service_state client_auth_service::state() const {
	return state_;
}

void client_auth_service::handle_banner(const_span payload) {
	ser::userauth_banner::load packet(payload);
	if(packet) {
		auto& [msg, lang] = packet;
		on_banner(msg);
	} else {
		log_.log(logger::error, "Invalid banner packet from server");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void client_auth_service::handle_success() {
	state_ = service_state::done;
	auto auth = std::move(auths_.front());
	auths_.pop_front();
	on_success(auth.username, auth.service);
}

void client_auth_service::handle_failure(const_span payload) {
	ser::userauth_failure::load packet(payload);
	if(packet) {
		auto auth = std::move(auths_.front());
		auths_.pop_front();

		auto& [auths, partial_success] = packet;
		// see if the single auth was actually successful but more is required
		if(partial_success) {
			on_auth_success(std::move(auth), auths);
		} else {
			on_auth_fail(std::move(auth), auths);
		}

	} else {
		log_.log(logger::error, "Invalid auth failure packet from server");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void client_auth_service::handle_pk_auth_ok(const_span payload) {
	log_.log(logger::debug, "public key auth ok from server");
}

void client_auth_service::handle_change_password(const_span payload) {
	log_.log(logger::debug, "Server requires password change -- not implemented");
}

handler_result client_auth_service::process(ssh_packet_type t, const_span payload) {
	log_.log(logger::debug_trace, "client_auth_service::process [type={}]", int(t));
	if(t == ssh_userauth_banner) {
		handle_banner(payload);
	} else {
		if(auths_.empty()) {
			log_.log(logger::error, "Received auth failure in bad state");
			transport_.set_error_and_disconnect(ssh_protocol_error);
			return handler_result::handled;
		}

		auth_type cur = auths_.front().type;
		if(t == ssh_userauth_success) {
			handle_success();
		} else if(t == ssh_userauth_failure) {
			handle_failure(payload);
		} else if(cur == auth_type::public_key && t == ssh_packet_type(ssh_auth_pk_ok)) {
			handle_pk_auth_ok(payload);
		} else if(cur == auth_type::password && t == ssh_packet_type(ssh_auth_password_changereq)) {
			handle_change_password(payload);
		} else {
			state_ = service_state::error;
			set_error(spssh_invalid_packet, "invalid packet");
			return handler_result::unknown;
		}
	}

	return handler_result::handled;
}

void client_auth_service::no_authentication(std::string username, std::string service) {
	log_.log(logger::debug_trace, "sending no auth [username={}, service={}]", username, service);
	if(transport_.send_packet<ser::userauth_request>(username, service, "none")) {
		auths_.emplace_back(auth_type::none, std::move(username), std::move(service));
	}
}

void client_auth_service::authenticate(std::string username, std::string service, std::string_view password) {
	log_.log(logger::debug_trace, "sending password auth [username={}, service={}]", username, service);
	if(transport_.send_packet<ser::userauth_password_request>(username, service, "password", false, password)) {
		auths_.emplace_back(auth_type::password, std::move(username), std::move(service));
	}
}

void client_auth_service::authenticate(std::string username, std::string service, ssh_private_key const& key) {
	log_.log(logger::debug_trace, "sending pk auth [username={}, service={}]", username, service);
	SPSSH_ASSERT(key.valid(), "invalid private key given for auth");

	auto pk = key.public_key();
	if(!pk.valid()) {
		log_.log(logger::error, "Could not construct public key from the private key");
		transport_.set_error_and_disconnect(spssh_invalid_data);
		return;
	}

	auto ser_pubkey = to_byte_vector(pk);

	byte_vector pk_req;
	bool ret = ser::serialise_to_vector<ser::userauth_pk_request>(
		pk_req,
		username,
		service,
		"publickey",
		true,
		to_string(key.type()),
		to_string_view(ser_pubkey));

	if(ret) {
		auto sig = key.sign(pk_req);

		std::size_t pk_req_size = pk_req.size();
		// resize so we can fit the signature at the end
		pk_req.resize(pk_req_size + 4 + sig.size());

		// write the signature at the end of the pk_req
		ssh_bf_writer w(span{pk_req.data()+pk_req_size, pk_req.data()+pk_req.size()});
		ret = w.write(to_string_view(sig));
	}

	if(ret) {
		if(transport_.send_payload(pk_req)) {
			auths_.emplace_back(auth_type::public_key, std::move(username), std::move(service));
		}
	} else {
		transport_.set_error_and_disconnect(spssh_invalid_data);
	}
}


default_client_auth::default_client_auth(ssh_transport& transport, client_config const& c)
: client_auth_service(transport)
, config_(c)
{
	if(c.username.empty() || c.service.empty()) {
		state_ = service_state::error;
		set_error(spssh_invalid_setup, "Username or service not set");
	} else {
		// try first without auth, this gives us the supported auth methods if auth is required
		no_authentication(config_.username, config_.service);
	}
}

void default_client_auth::populate(std::vector<std::string_view> const& methods) {
	if(auths_.empty()) {
		if(std::find(methods.begin(), methods.end(), "publickey") != methods.end()) {
			for(auto& k : config_.private_keys) {
				auths_.push_back(
					[&]	{
						authenticate(config_.username, config_.service, k.key);
					});
			}
		}
		if(!config_.password.empty() && std::find(methods.begin(), methods.end(), "password") != methods.end()) {
			auths_.push_back(
				[&]	{
					authenticate(config_.username, config_.service, config_.password);
				});
		}
	}
}

void default_client_auth::next() {
	if(!auths_.empty()) {
		auths_.front()();
		auths_.pop_front();
	} else {
		state_ = service_state::error;
		set_error(ssh_no_more_auth_methods_available, "Could not authenticate with any methods we have");
	}
}

void default_client_auth::on_banner(std::string_view m) {
	log_.log(logger::info, "banner: {}", m);
}

void default_client_auth::on_auth_fail(auth_try auth, std::vector<std::string_view> const& methods) {
	log_.log(logger::debug_trace, "on_auth_fail [methods={}]", to_string(methods));
	if(auth.type == auth_type::none) {
		populate(methods);
	}
	next();
}

void default_client_auth::on_auth_success(auth_try auth, std::vector<std::string_view> const& methods) {
	log_.log(logger::debug_trace, "on_auth_success [methods={}]", to_string(methods));
	next();
}

void default_client_auth::on_success(std::string_view username, std::string_view service) {
	log_.log(logger::info, "auth succeeded [username={}, service={}]", username, service);
}

}