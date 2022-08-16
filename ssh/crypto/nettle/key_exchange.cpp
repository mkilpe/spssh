
#include "nettle_helper.hpp"
#include "util.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/key_exchange.hpp"

#include <nettle/curve25519.h>

namespace securepath::ssh::nettle {

class X25519_key_exchange : public key_exchange {
public:
	X25519_key_exchange(crypto_call_context const& c)
	: context_(c)
	{
		context_.log.log(logger::debug_trace, "constructing X25519_key_exchange");

		priv_.resize(CURVE25519_SIZE);
		context_.rand.random_bytes(priv_);
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

	crypto_call_context context_;
	byte_vector pub_;
	byte_vector priv_;
};

static void extract_rand(void *ctx, size_t length, uint8_t *dst) {
	random& r = *(random*)ctx;
	r.random_bytes(span((std::byte*)dst, length));
}

class dh_key_exchange : public key_exchange {
public:
	dh_key_exchange(key_exchange_type t, crypto_call_context const& c, const_span modulus, const_span generator)
	: context_(c)
	, type_(t)
	, p_(modulus) // p is a large safe prime
	{
		context_.log.log(logger::debug_trace, "constructing dh_key_exchange");

		// g is a generator for a subgroup of GF(p)
		integer g(generator);

		// q is the order of the subgroup, calculate q = (p − 1) / 2
		integer q(p_);
		mpz_sub_ui(q, q, 1);
		mpz_div_ui(q, q, 2);

		// make random y (0 < y < q), substract one and then increase after creating the random to get correct range
		mpz_sub_ui(q, q, 1);

		// sets random 0 <= y < q
		nettle_mpz_random(y_, &context_.rand, extract_rand, q);
		mpz_add_ui(y_, y_, 1);

		integer e;
		// calculate e = g^y mod p
		mpz_powm(e, g, y_, p_);

		//check that 1 < e < p-1
		is_valid_ = check_valid_public_key(e);
		if(is_valid_) {
			// save the public part
			pubkey_.resize(nettle_mpz_sizeinbase_256_u(e));
			nettle_mpz_get_str_256(pubkey_.size(), to_uint8_ptr(pubkey_), e);
		}
	}

	template<typename Modp>
	dh_key_exchange(key_exchange_type t, crypto_call_context const& c, Modp const& m)
	: dh_key_exchange(t, c, m.modulus(), m.generator())
	{
	}

	bool is_valid() const {
		return is_valid_;
	}

	key_exchange_type type() const override {
		return type_;
	}

	const_span public_key() const override {
		return pubkey_;
	}

	bool check_valid_public_key(mpz_t e) const {
		integer p_1(p_);
		mpz_sub_ui(p_1, p_1, 1);
		return mpz_cmp_ui(e, 1) > 0 && mpz_cmp(e, p_1) < 0;
	}

	byte_vector agree(const_span remote_public) override {
		if(remote_public.empty()) {
			return {};
		}

		byte_vector res;
		integer f(remote_public);

		if(check_valid_public_key(f)) {
			integer k;

			//k = f^y mod p
			mpz_powm(k, f, y_, p_);
			res.resize(nettle_mpz_sizeinbase_256_u(k));
			nettle_mpz_get_str_256(res.size(), to_uint8_ptr(res), k);
		}

		return res;
	}

	crypto_call_context context_;
	key_exchange_type type_;
	bool is_valid_{};
	integer p_;
	integer y_;
	byte_vector pubkey_;
};

// 2048-bit MODP Group from RFC 3526
struct modp_group_14 {
	static auto modulus() {
		return modp_group_14_modulus();
	}

	static auto generator() {
		return modp_group_14_generator();
	}
};

// 4096-bit MODP Group from RFC 3526
struct modp_group_16 {
	static auto modulus() {
		return modp_group_16_modulus();
	}

	static auto generator() {
		return modp_group_16_generator();
	}
};


std::unique_ptr<ssh::key_exchange> create_key_exchange(key_exchange_data const& d, crypto_call_context const& c) {
	if(d.type() == key_exchange_type::X25519) {
		return std::make_unique<X25519_key_exchange>(c);
	} else if(d.type() == key_exchange_type::dh_group14) {
		auto p = std::make_unique<dh_key_exchange>(d.type(), c, modp_group_14{});
		if(p->is_valid()) {
			return p;
		}
	} else if(d.type() == key_exchange_type::dh_group16) {
		auto p = std::make_unique<dh_key_exchange>(d.type(), c, modp_group_16{});
		if(p->is_valid()) {
			return p;
		}
	}
	return nullptr;
}

}

