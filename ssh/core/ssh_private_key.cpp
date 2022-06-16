#include "ssh_private_key.hpp"
#include "ssh_binary_util.hpp"

#include "ssh/crypto/private_key.hpp"

namespace securepath::ssh {

ssh_private_key::ssh_private_key(std::shared_ptr<private_key> i, std::string_view comment)
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

static std::string to_ecdsa_signature_blob(const_span s) {
	std::string res;
	string_binout out(res);
	ssh_bf_binout_writer w(out);

	w.write(const_mpint_span{safe_subspan(s, 0, s.size()/2)});
	w.write(const_mpint_span{safe_subspan(s, s.size()/2, s.size()/2)});

	return res;
}

byte_vector ssh_private_key::sign(const_span in) const {
	auto t = type();
	if(t == key_type::unknown) {
		return {};
	}

	byte_vector res;
	byte_vector signature;
	signature.resize(key_impl_->signature_size());

	if(key_impl_->sign(in, signature)) {
		byte_vector_binout out(res);
		ssh_bf_binout_writer w(out);

		w.write(to_string(t));
		if(t == key_type::ecdsa_sha2_nistp256) {
			w.write(to_ecdsa_signature_blob(signature));
		} else {
			w.write(to_string_view(signature));
		}
	}
	return res;
}

static ssh_private_key load_raw_ed25519_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
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

static ssh_private_key load_raw_rsa_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
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

static ssh_private_key load_raw_ecdsa_private_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call) {
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

static ssh_private_key load_raw_ssh_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call) {
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

ssh_private_key load_raw_ssh_private_key(const_span data, crypto_context const& crypto, crypto_call_context const& call) {
	ssh_bf_reader r(data);
	return load_raw_ssh_private_key(r, crypto, call);
}

ssh_private_key load_raw_base64_ssh_private_key(std::string_view s, crypto_context const& crypto, crypto_call_context const& call) {
	return load_raw_ssh_private_key(decode_base64(s), crypto, call);
}

// the magic string in beginning of openssh format (including the null char)
char const magic[] = "openssh-key-v1";

static ssh_private_key load_raw_openssh_private_key(const_span data, crypto_context const& crypto, crypto_call_context const& call) {
	ssh_bf_reader r(data);

	std::optional<std::span<std::byte const, sizeof(magic)>> m;
	if(!r.read(m) || std::memcmp(m->data(), magic, sizeof(magic)) != 0) {
		call.log.log(logger::error, "Failed to find openssh magic string");
		return {};
	}

	std::string_view cipher;
	if(!r.read(cipher) || cipher != "none") {
		call.log.log(logger::error, "Not supporting encrypted private key files");
		return {};
	}

	std::string_view kdf;
	if(!r.read(kdf) || kdf != "none") {
		call.log.log(logger::error, "Not supporting encrypted private key files");
		return {};
	}

	std::string_view kdf_options;
	if(!r.read(kdf_options) || kdf_options != "") {
		call.log.log(logger::error, "Not supporting encrypted private key files");
		return {};
	}

	std::uint32_t pk_count = 0;
	if(!r.read(pk_count)) {
		call.log.log(logger::error, "Invalid private key (could not read public key count)");
		return {};
	}

	// read out the public keys and ignore, we want only the private key
	for(std::uint32_t i = 0; i != pk_count; ++i) {
		std::string_view pk;
		if(!r.read(pk)) {
			call.log.log(logger::error, "Invalid private key (failed reading public key)");
			return {};
		}
	}

	std::string_view priv_keys;
	if(!r.read(priv_keys)) {
		call.log.log(logger::error, "Invalid private key (failed to read private key parts)");
		return {};
	}

	ssh_bf_reader priv_r(to_span(priv_keys));

	// these are the check integers that can be used to check if the key was decrypted successfully
	std::uint32_t n1 = 0, n2 = 0;
	if(!priv_r.read(n1) || !priv_r.read(n2) || n1 != n2) {
		call.log.log(logger::error, "Invalid private key (failed to read check integers or they don't match)");
		return {};
	}

	return load_raw_ssh_private_key(priv_r, crypto, call);
}

static ssh_private_key load_base64_openssh_private_key(std::string_view encoded_data, crypto_context const& crypto, crypto_call_context const& call) {
	ssh_private_key key;
	auto data = decode_base64(encoded_data);
	if(!data.empty()) {
		key = load_raw_openssh_private_key(data, crypto, call);
	}
	return key;
}

std::string_view const openssh_start = "-----BEGIN OPENSSH PRIVATE KEY-----";
std::string_view const openssh_end   = "-----END OPENSSH PRIVATE KEY-----";

ssh_private_key load_ssh_private_key(const_span data, crypto_context const& crypto, crypto_call_context const& call) {
	ssh_private_key key;
	auto view = to_string_view(data);
	if(view.starts_with(openssh_start)) {

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
		key = load_base64_openssh_private_key(encoded_data, crypto, call);
	}
	return key;
}

}
