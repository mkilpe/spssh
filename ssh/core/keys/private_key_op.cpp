#include "private_key_op.hpp"

#include "ssh/core/ssh_private_key.hpp"
#include "ssh/core/ssh_binary_util.hpp"

namespace securepath::ssh {

std::string to_ecdsa_signature_blob(const_span s) {
	std::string res;
	string_binout out(res);
	ssh_bf_binout_writer w(out);

	w.write(const_mpint_span{safe_subspan(s, 0, s.size()/2)});
	w.write(const_mpint_span{safe_subspan(s, s.size()/2, s.size()/2)});

	return res;
}

ssh_private_key load_raw_ed25519_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading ed25519 private key");
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

ssh_private_key load_raw_rsa_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading rsa private key");
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

ssh_private_key load_raw_ecdsa_private_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call) {
	call.log.log(logger::debug_trace, "Loading ecdsa private key");
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

ssh_private_key load_raw_ssh_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
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

// the magic string in beginning of openssh format (including the null char)
char const magic[] = "openssh-key-v1";
std::string_view const openssh_start = "-----BEGIN OPENSSH PRIVATE KEY-----";
std::string_view const openssh_end   = "-----END OPENSSH PRIVATE KEY-----";

bool is_openssh_private_key(const_span data) {
	auto view = to_string_view(data);
	return view.starts_with(openssh_start);
}

openssh_private_key::openssh_private_key(const_span data, crypto_context const& crypto, crypto_call_context const& call)
: crypto_(crypto)
, call_(call)
{
	if(is_openssh_private_key(data)) {
		auto view = to_string_view(data);
		// get the base64 encoded string
		std::string encoded_data;
		view = view.substr(openssh_start.size());
		for(std::string_view::size_type p = view.find_first_of("\n\r")
			; p != std::string_view::npos && !view.starts_with(openssh_end)
			; p = view.find_first_of("\n\r"))
		{
			if(p) {
				encoded_data += view.substr(0, p);
			}
			view = view.substr(p+1);
		}
		data_ = decode_base64(encoded_data);
		if(!data_.empty()) {
			if(!extract_info()) {
				data_.clear();
			}
		}
	}
}

bool openssh_private_key::is_valid() const {
	return !data_.empty();
}

bool openssh_private_key::is_encrypted() const {
	return is_encrypted_;
}

bool openssh_private_key::extract_info() {
	ssh_bf_reader r(data_);

	std::optional<std::span<std::byte const, sizeof(magic)>> m;
	if(!r.read(m) || std::memcmp(m->data(), magic, sizeof(magic)) != 0) {
		call_.log.log(logger::error, "Failed to find openssh magic string");
		return false;
	}

	std::string_view cipher;
	if(!r.read(cipher)) {
		call_.log.log(logger::error, "Failed to read cipher");
		return false;
	}

	is_encrypted_ = cipher != "none";

	std::string_view kdf;
	if(!r.read(kdf) || (!is_encrypted_ && kdf != "none")) {
		call_.log.log(logger::error, "Failed to read or bad kdf");
		return false;
	}

	std::string_view kdf_options;
	if(!r.read(kdf_options) || (!is_encrypted_ && kdf_options != "")) {
		call_.log.log(logger::error, "Failed to read or bad kdf options");
		return false;
	}

	std::uint32_t pk_count = 0;
	if(!r.read(pk_count)) {
		call_.log.log(logger::error, "Failed to read public key count");
		return false;
	}

	// read out the public keys and ignore, we want only the private key
	for(std::uint32_t i = 0; i != pk_count; ++i) {
		std::string_view pk;
		if(!r.read(pk)) {
			call_.log.log(logger::error, "Failed to read public keys");
			return false;
		}
	}

	if(!r.read(priv_keys_)) {
		call_.log.log(logger::error, "Failed to read private key parts");
		return false;
	}

	return true;
}

ssh_private_key openssh_private_key::construct() const {
	ssh_bf_reader priv_r(to_span(priv_keys_));

	// these are the check integers that can be used to check if the key was decrypted successfully
	std::uint32_t n1 = 0, n2 = 0;
	if(!priv_r.read(n1) || !priv_r.read(n2) || n1 != n2) {
		call_.log.log(logger::error, "Failed to read check integers or they don't match (encrypted private key?)");
		return {};
	}

	return load_raw_ssh_private_key(priv_r, crypto_, call_);
}

}
