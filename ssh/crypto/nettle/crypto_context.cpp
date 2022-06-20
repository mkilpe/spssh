
#include "crypto_context.hpp"

namespace securepath::ssh::nettle {

std::unique_ptr<ssh::random> create_random();
std::unique_ptr<ssh::cipher> create_cipher(cipher_type, cipher_dir dir, const_span secret, const_span iv, crypto_call_context const&);
std::unique_ptr<ssh::mac> create_mac(mac_type, const_span secret, crypto_call_context const&);
std::shared_ptr<ssh::public_key> create_public_key(public_key_data const&, crypto_call_context const&);
std::shared_ptr<ssh::private_key> create_private_key(private_key_data const&, crypto_call_context const&);
std::unique_ptr<ssh::key_exchange> create_key_exchange(key_exchange_data const&, crypto_call_context const&);
std::unique_ptr<ssh::hash> create_hash(hash_type, crypto_call_context const&);
std::shared_ptr<ssh::private_key> generate_private_key(private_key_info const&, crypto_call_context const&);

crypto_context create_nettle_context() {
	return crypto_context{
			create_random,
			create_cipher,
			create_mac,
			create_public_key,
			create_private_key,
			create_key_exchange,
			create_hash,
			generate_private_key
		};
}

}
