
#include "util.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/key_exchange.hpp"

#include <nettle/curve25519.h>

namespace securepath::ssh::nettle {

class X25519_key_exchange : public key_exchange {
public:
	X25519_key_exchange(crypto_call_context const& c)
	: context(c)
	{
		priv_.resize(CURVE25519_SIZE);
		context.rand.random_bytes(priv_);
		clamp25519(priv_);

		pub_.resize(CURVE25519_SIZE);
		curve25519_mul_g(to_uint8_ptr(pub_), to_uint8_ptr(priv_));
	}

	const_span public_key() const override {
		return pub_;
	}

	std::vector<std::byte> agree(const_span remote_public) override {
		if(remote_public.size() != CURVE25519_SIZE) {
			return {};
		}

		std::vector<std::byte> res;
		res.resize(CURVE25519_SIZE);
		nettle_curve25519_mul(
			to_uint8_ptr(res),
			to_uint8_ptr(priv_),
			to_uint8_ptr(remote_public));

		return res;
	}

	crypto_call_context context;
	std::vector<std::byte> pub_;
	std::vector<std::byte> priv_;
};

std::unique_ptr<ssh::key_exchange> create_key_exchange(key_exchange_type t, crypto_call_context const& c) {
	if(t == key_exchange_type::X25519) {
		return std::make_unique<X25519_key_exchange>(c);
	}
	return nullptr;
}

}
