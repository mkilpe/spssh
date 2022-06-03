
#include "ssh_public_key.hpp"
#include "ssh_binary_util.hpp"

namespace securepath::ssh {

ssh_public_key::ssh_public_key(std::shared_ptr<public_key> pkey)
: key_impl_(std::move(pkey))
{
}

key_type ssh_public_key::type() const {
	return key_impl_ ? key_impl_->type() : key_type::unknown;
}

bool ssh_public_key::valid() const {
	return static_cast<bool>(key_impl_);
}

static byte_vector ecdsa_sig(std::string_view payload) {
	ssh_bf_reader r(to_span(payload));
	std::string_view p1, p2;
	if(!r.read(p1) || !r.read(p2)) {
		return {};
	}
	auto pi1 = to_umpint(p1);
	auto pi2 = to_umpint(p2);
	byte_vector sig;
	sig.insert(sig.end(), pi1.data.begin(), pi1.data.end());
	sig.insert(sig.end(), pi2.data.begin(), pi2.data.end());
	return sig;
}

bool ssh_public_key::verify(const_span msg, const_span signature) const {
	auto t = type();
	if(t == key_type::unknown) {
		return false;
	}

	ssh_bf_reader r(signature);
	std::string_view type;
	std::string_view payload;
	if(!r.read(type) || type != to_string(t) || !r.read(payload)) {
		return false;
	}

	if(t == key_type::ecdsa_sha2_nistp256) {
		return key_impl_->verify(msg, ecdsa_sig(payload));
	} else {
		return key_impl_->verify(msg, to_span(payload));
	}
}

static bool ser_ed25519_public_key(ssh_bf_binout_writer& w, public_key const& key) {
	ed25519_public_key_data data;
	return key.fill_data(data) && w.write(to_string_view(data.pubkey));
}

static bool ser_rsa_public_key(ssh_bf_binout_writer& w, public_key const& key) {
	rsa_public_key_data data;
	return key.fill_data(data) && w.write(data.e) && w.write(data.n);
}

static bool ser_ecdsa_public_key(ssh_bf_binout_writer& w, public_key const& key) {
	ecdsa_public_key_data data{key_type::ecdsa_sha2_nistp256};
	return key.fill_data(data) && w.write(to_curve_name(data.ecdsa_type)) && w.write(to_string_view(data.ecc_point));
}

bool ssh_public_key::serialise(binout& out) const {
	bool result = false;
	ssh_bf_binout_writer w(out);

	using enum key_type;
	auto t = type();

	if(t != unknown) {
		w.write(to_string(t));
	}

	if(t == ssh_ed25519) {
		return ser_ed25519_public_key(w, *key_impl_);
	} else if(t == ssh_rsa) {
		return ser_rsa_public_key(w, *key_impl_);
	} else if(t == ecdsa_sha2_nistp256) {
		return ser_ecdsa_public_key(w, *key_impl_);
	}
	return false;
}

std::string ssh_public_key::fingerprint(crypto_context const& crypto, crypto_call_context const& call) const {
	std::string res;
	if(valid()) {
		auto sha256 = crypto.construct_hash(hash_type::sha2_256, call);
		if(sha256) {
			hash_binout bo(*sha256);
			if(serialise(bo)) {
				res = "SHA256:" + encode_base64(sha256->digest());
			}
		}
	}
	return res;
}

static ssh_public_key load_ed25519_public_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading ssh ed25519 public key");
	std::string_view pubkey;
	if(r.read(pubkey)) {
		if(pubkey.size() == ed25519_key_size) {
			ed25519_public_key_data data{to_span(pubkey)};
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
	call.log.log(logger::debug_trace, "Loading ssh rsa public key");
	std::string_view e, n;
	if(r.read(e) && r.read(n)) {
		return ssh_public_key(crypto.construct_public_key(rsa_public_key_data{to_umpint(e), to_umpint(n)}, call));
	} else {
		call.log.log(logger::debug_trace, "Failed to read ssh rsa public key");
	}
	return {};
}

static ssh_public_key load_ecdsa_public_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading ssh ecdsa public key");
	std::string_view curve, ecc_point;
	if(r.read(curve) && r.read(ecc_point)) {
		if("ecdsa-sha2-" + std::string(curve) == type) {
			return ssh_public_key(crypto.construct_public_key(
				ecdsa_public_key_data{key_type::ecdsa_sha2_nistp256, to_span(ecc_point)}, call));
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

byte_vector to_byte_vector(ssh_public_key const& k) {
	byte_vector v;
	byte_vector_binout s(v);
	return k.serialise(s) ? v : byte_vector{};
}

}
