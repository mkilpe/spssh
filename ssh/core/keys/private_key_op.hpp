#ifndef SP_SHH_CORE_KEYS_PRIVATE_KEY_OP_HEADER
#define SP_SHH_CORE_KEYS_PRIVATE_KEY_OP_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

class ssh_private_key;
class private_key;
class ssh_bf_reader;
class ssh_bf_binout_writer;
class crypto_context;
class crypto_call_context;

std::string to_ecdsa_signature_blob(const_span s);
bool ser_ed25519_private_key(ssh_bf_binout_writer& w, private_key const& key, std::string_view comment);
bool ser_rsa_private_key(ssh_bf_binout_writer& w, private_key const& key, std::string_view comment);
bool ser_ecdsa_private_key(ssh_bf_binout_writer& w, private_key const& key, std::string_view comment);
ssh_private_key load_raw_ed25519_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call);
ssh_private_key load_raw_rsa_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call);
ssh_private_key load_raw_ecdsa_private_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call);
ssh_private_key load_raw_ssh_private_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call);

bool is_openssh_private_key(std::string_view);

class openssh_private_key {
public:
	/// Load key from text data
	openssh_private_key(std::string_view, crypto_context const& crypto, crypto_call_context const& call);

	/// Set from ssh_private_key
	openssh_private_key(ssh_private_key const&, crypto_context const& crypto, crypto_call_context const& call);

	bool is_valid() const;
	bool is_encrypted() const;

	ssh_private_key construct() const;
	std::string serialise() const;

private:
	bool extract_info();
	bool construct_info(ssh_private_key const& key);

private:
	crypto_context const& crypto_;
	crypto_call_context const& call_;
	byte_vector data_;
	bool is_encrypted_{};
	std::string_view priv_keys_;
};

}

#endif
