#ifndef SP_SHH_CORE_KEYS_PUBLIC_KEY_OP_HEADER
#define SP_SHH_CORE_KEYS_PUBLIC_KEY_OP_HEADER

#include <string_view>
#include "ssh/common/types.hpp"

namespace securepath::ssh {

class ssh_bf_binout_writer;
class ssh_bf_reader;
class public_key;
class crypto_context;
class crypto_call_context;
class ssh_public_key;

byte_vector ecdsa_sig(std::string_view payload);
bool ser_ed25519_public_key(ssh_bf_binout_writer& w, public_key const& key);
bool ser_rsa_public_key(ssh_bf_binout_writer& w, public_key const& key);
bool ser_ecdsa_public_key(ssh_bf_binout_writer& w, public_key const& key);
ssh_public_key load_ed25519_public_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call);
ssh_public_key load_rsa_public_key(ssh_bf_reader& r, crypto_context const& crypto, crypto_call_context const& call);
ssh_public_key load_ecdsa_public_key(ssh_bf_reader& r, std::string_view type, crypto_context const& crypto, crypto_call_context const& call);

}

#endif
