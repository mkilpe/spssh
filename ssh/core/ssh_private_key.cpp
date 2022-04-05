#include "ssh_private_key.hpp"
#include "ssh_binary_util.hpp"

#include "ssh/crypto/private_key.hpp"

namespace securepath::ssh {

ssh_private_key::ssh_private_key(std::unique_ptr<private_key> i, std::string_view comment)
: key_impl_(std::move(i))
, comment_(comment)
{
}

key_type ssh_private_key::type() const {
	return key_impl_ ? key_impl_->type() : key_type::unknown;
}

ssh_public_key ssh_private_key::public_key() const {
	return key_impl_ ? ssh_public_key{key_impl_->public_key()} : ssh_public_key{};
}

bool ssh_private_key::valid() const {
	return static_cast<bool>(key_impl_);
}

std::size_t ssh_private_key::signature_size() const {
	return key_impl_ ? key_impl_->signature_size() : 0;
}

void ssh_private_key::sign(const_span in, span out) const {
	SPSSH_ASSERT(key_impl_, "invalid private key");
	key_impl_->sign(in, out);
}

byte_vector ssh_private_key::sign(const_span in) const {
	SPSSH_ASSERT(key_impl_, "invalid private key");
	return key_impl_->sign(in);
}

static ssh_private_key load_raw_ed25519_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Trying to load ed25519 private key");
	std::string_view pubkey;
	std::string_view privkey;
	std::string_view comment;
	if(r.read(pubkey) && r.read(privkey) && r.read(comment)) {
		if(pubkey.size() == ed25519_key_size && privkey.size() == ed25519_key_size || privkey.size() == 2*ed25519_key_size) {
			auto pub_bytes = to_span(pubkey);
			// openssh has 64 bytes in the private key part, apparently the public key is repeated in the latter 32 bytes
			auto priv_bytes = to_span(privkey).subspan(0, ed25519_key_size);

			ed25519_private_key_data data{
				ed25519_private_key_data::value_type(priv_bytes.data(), priv_bytes.size()),
				ed25519_private_key_data::value_type(pub_bytes.data(), pub_bytes.size())
			};
			return ssh_private_key(crypto.construct_private_key(data, call), comment);
		} else {
			call.log.log(logger::debug_trace, "ed25519 public or private key size not correct");
		}
	} else {
		call.log.log(logger::debug_trace, "Failed to read ed25519 private key");
	}
	return {};
}

static ssh_private_key load_raw_rsa_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Trying to load rsa private key");
	std::string_view n, e, d, iqmp, p, q;
	std::string_view comment;
	if(r.read(n) && r.read(e) && r.read(d) && r.read(iqmp) && r.read(p) && r.read(q) && r.read(comment)) {
		rsa_private_key_data data{to_umpint(e), to_umpint(n), to_umpint(d),	to_umpint(p), to_umpint(q)};
		return ssh_private_key(crypto.construct_private_key(data, call), comment);
	} else {
		call.log.log(logger::debug_trace, "Failed to read rsa private key");
	}
	return {};
}

static ssh_private_key load_raw_ecdsa_private_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Trying to load ecdsa private key");
	std::string_view curve;
	std::string_view ecc_point; // public key
	std::string_view privkey;
	std::string_view comment;
	if(r.read(curve) && r.read(ecc_point) && r.read(privkey) && r.read(comment)) {
		if("ecdsa-sha2-" + std::string(curve) == type) {
			ecdsa_private_key_data data{key_type::ecdsa_sha2_nistp256, to_span(ecc_point), to_umpint(privkey)};
			return ssh_private_key(crypto.construct_private_key(data, call), comment);
		} else {
			call.log.log(logger::debug_trace, "Invalid ecdsa private key");
		}
	} else {
		call.log.log(logger::debug_trace, "Failed to read ecdsa private key");
	}
	return {};
}

ssh_private_key load_raw_ssh_private_key(const_span data, crypto_context const& crypto, crypto_call_context const& call) {
	ssh_bf_reader r(data);
	std::string_view type;
	if(r.read(type)) {
		if(type == "ssh-ed25519") {
			return load_raw_ed25519_private_key(r, crypto, call);
		} else if(type == "ssh-rsa") {
			return load_raw_rsa_private_key(r, crypto, call);
		} else if(type == "ecdsa-sha2-nistp256") {
			return load_raw_ecdsa_private_key(r, type, crypto, call);
		}
	}
	return {};
}

ssh_private_key load_raw_base64_ssh_private_key(std::string_view s, crypto_context const& crypto, crypto_call_context const& call) {
	return load_raw_ssh_private_key(decode_base64(s), crypto, call);
}

}
