#include "ssh_private_key.hpp"
#include "ssh_binary_util.hpp"
#include "keys/private_key_op.hpp"

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


ssh_private_key load_raw_ssh_private_key(const_span data, crypto_context const& crypto, crypto_call_context const& call) {
	ssh_bf_reader r(data);
	return load_raw_ssh_private_key(r, crypto, call);
}

ssh_private_key load_raw_base64_ssh_private_key(std::string_view s, crypto_context const& crypto, crypto_call_context const& call) {
	return load_raw_ssh_private_key(decode_base64(s), crypto, call);
}


ssh_private_key load_ssh_private_key(const_span data, crypto_context const& crypto, crypto_call_context const& call) {
	ssh_private_key key;
	if(is_openssh_private_key(data)) {
		openssh_private_key k(data, crypto, call);
		if(k.is_valid()) {
			if(!k.is_encrypted()) {
				key = k.construct();
			} else {
				call.log.log(logger::error, "encrypted openssh private key not supported");
			}
		} else {
			call.log.log(logger::error, "invalid openssh private key");
		}
	}
	return key;
}

}
