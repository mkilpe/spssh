
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/key_exchange.hpp"

namespace securepath::ssh::nettle {

class X25519_key_exchange : public key_exchange {
public:
	X25519_key_exchange(crypto_call_context const& c)
	: context(c)
	{}

	const_span public_key() const override {
		return {};
	}

	std::vector<std::byte> agree(const_span remote_public) override {
		return {};
	}

	crypto_call_context context;
};

std::unique_ptr<ssh::key_exchange> create_key_exchange(key_exchange_type t, crypto_call_context const& c) {
	if(t == key_exchange_type::X25519) {
		return std::make_unique<X25519_key_exchange>(c);
	}
	return nullptr;
}

}

