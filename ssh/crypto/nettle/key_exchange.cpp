
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
		context.log.log(logger::debug_trace, "constructing X25519_key_exchange");

		priv_.resize(CURVE25519_SIZE);
		context.rand.random_bytes(priv_);
		clamp25519(priv_);

		pub_.resize(CURVE25519_SIZE);
		curve25519_mul_g(to_uint8_ptr(pub_), to_uint8_ptr(priv_));
	}

	key_exchange_type type() const override {
		return key_exchange_type::X25519;
	}

	const_span public_key() const override {
		return pub_;
	}

	byte_vector agree(const_span remote_public) override {
		if(remote_public.size() != CURVE25519_SIZE) {
			return {};
		}

		byte_vector res;
		res.resize(CURVE25519_SIZE);
		nettle_curve25519_mul(
			to_uint8_ptr(res),
			to_uint8_ptr(priv_),
			to_uint8_ptr(remote_public));

		return res;
	}

	crypto_call_context context;
	byte_vector pub_;
	byte_vector priv_;
};

std::unique_ptr<ssh::key_exchange> create_key_exchange(key_exchange_data const& d, crypto_call_context const& c) {
	if(d.type() == key_exchange_type::X25519) {
		return std::make_unique<X25519_key_exchange>(c);
	}
	return nullptr;
}

}

/*
DH:

p is a large safe prime
g is a generator for a subgroup of GF(p)
q is the order of the subgroup

Client:

mpz_set(i, q);
mpz_sub_ui(i, i, 2);
nettle_mpz_random(x, NULL, rnd_func, i);
mpz_add_ui(x, x, 2);

mpz_powm(e, g, x, p);

send e to server


Server:

mpz_set(i, q);
mpz_sub_ui(i, i, 1);
nettle_mpz_random(y, NULL, rnd_func, i);
mpz_add_ui(y, y, 1);

mpz_powm(f, g, y, p);

receive e from client

mpz_powm(k, e, y, p);


check:
1 < e < p-1
1 < f < p-1


should we use key generation from here: NIST SP 800-56Ar3 5.6.1.1.3
*/
