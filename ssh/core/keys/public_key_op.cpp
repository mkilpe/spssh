#include "public_key_op.hpp"

#include "ssh/core/ssh_public_key.hpp"
#include "ssh/core/ssh_binary_util.hpp"

namespace securepath::ssh {

byte_vector ecdsa_sig(std::string_view payload) {
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

bool ser_ed25519_public_key(ssh_bf_binout_writer& w, public_key const& key) {
	ed25519_public_key_data data;
	return key.fill_data(data) && w.write(to_string_view(data.pubkey));
}

bool ser_rsa_public_key(ssh_bf_binout_writer& w, public_key const& key) {
	rsa_public_key_data data;
	return key.fill_data(data) && w.write(data.e) && w.write(data.n);
}

bool ser_ecdsa_public_key(ssh_bf_binout_writer& w, public_key const& key) {
	ecdsa_public_key_data data{key_type::ecdsa_sha2_nistp256};
	return key.fill_data(data) && w.write(to_curve_name(data.ecdsa_type)) && w.write(to_string_view(data.ecc_point));
}

ssh_public_key load_ed25519_public_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
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

ssh_public_key load_rsa_public_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading ssh rsa public key");
	std::string_view e, n;
	if(r.read(e) && r.read(n)) {
		return ssh_public_key(crypto.construct_public_key(rsa_public_key_data{to_umpint(e), to_umpint(n)}, call));
	} else {
		call.log.log(logger::debug_trace, "Failed to read ssh rsa public key");
	}
	return {};
}

ssh_public_key load_ecdsa_public_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call) {
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

}
