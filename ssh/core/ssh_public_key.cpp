
#include "ssh_public_key.hpp"
#include "ssh_binary_util.hpp"

namespace securepath::ssh {

ssh_public_key::ssh_public_key(std::unique_ptr<public_key> pkey)
: key_impl_(std::move(pkey))
{
}

key_type ssh_public_key::type() const {
	return key_impl_ ? key_impl_->type() : key_type::unknown;
}

bool ssh_public_key::valid() const {
	return static_cast<bool>(key_impl_);
}

bool ssh_public_key::verify(const_span msg, const_span signature) const {
	return key_impl_ ? key_impl_->verify(msg, signature) : false;
}

static ssh_public_key load_ed25519_public_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Trying to load ssh ed25519 public key");
	std::string_view pubkey;
	if(r.read(pubkey)) {
		if(pubkey.size() == ed25519_key_size) {
			auto bytes = to_span(pubkey);
			ed25519_public_key_data data{ed25519_public_key_data::value_type(bytes.data(), bytes.size())};
			return ssh_public_key(crypto.construct_public_key(data, call));
		} else {
			call.log.log(logger::debug_trace, "ssh ed25519 public key size not correct");
		}
	} else {
		call.log.log(logger::debug_trace, "Failed to read ssh ed25519 public key");
	}
	return {};
}

static ssh_public_key load_rsa_public_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Trying to load ssh rsa public key");
	std::string_view e, n;
	if(r.read(e) && r.read(n)) {
		return ssh_public_key(crypto.construct_public_key(rsa_public_key_data{to_span(e), to_span(n)}, call));
	} else {
		call.log.log(logger::debug_trace, "Failed to read ssh rsa public key");
	}
	return {};
}

static ssh_public_key load_ecdsa_public_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Trying to load ssh ecdsa public key");
	std::string_view curve, ecc_point;
	if(r.read(curve) && r.read(ecc_point)) {
		if("ecdsa-sha2-" + std::string(curve) == type) {
			return ssh_public_key(crypto.construct_public_key(ecdsa_public_key_data{curve, to_span(ecc_point)}, call));
		} else {
			call.log.log(logger::debug_trace, "Invalid ecdsa public key");
		}
	} else {
		call.log.log(logger::debug_trace, "Failed to read ssh ecdsa public key");
	}
	return {};
}

ssh_public_key load_ssh_public_key(const_span data, crypto_context const& crypto, crypto_call_context const& call) {
	ssh_bf_reader r(data);
	std::string_view type;
	if(r.read(type)) {
		if(type == "ssh-ed25519") {
			return load_ed25519_public_key(r, crypto, call);
		} else if(type == "ssh-rsa") {
			return load_rsa_public_key(r, crypto, call);
		} else if(type == "ecdsa-sha2-nistp256") {
			return load_ecdsa_public_key(r, type, crypto, call);
		} else {
			call.log.log(logger::debug_trace, "Invalid type: {}", type);
		}
	}
	return {};
}

ssh_public_key load_base64_ssh_public_key(std::string_view s, crypto_context const& crypto, crypto_call_context const& call) {
	return load_ssh_public_key(decode_base64(s), crypto, call);
}

}
