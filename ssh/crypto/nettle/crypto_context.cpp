
#include "crypto_context.hpp"

namespace securepath::ssh::nettle {

std::unique_ptr<ssh::random> create_random();
std::unique_ptr<ssh::cipher> create_cipher(cipher_type, crypto_call_context const&);
std::unique_ptr<ssh::mac> create_mac(mac_type, crypto_call_context const&);
std::unique_ptr<ssh::key_exchange> create_key_exchange(key_exchange_type, crypto_call_context const&);

crypto_context create_nettle_context() {
	return crypto_context{
			create_random,
			create_cipher,
			create_mac,
			nullptr,
			nullptr,
			create_key_exchange
		};
}

}
