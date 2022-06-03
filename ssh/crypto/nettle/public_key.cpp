
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/ids.hpp"
#include <memory>

#include <nettle/bignum.h>
#include <nettle/ecdsa.h>
#include <nettle/eddsa.h>
#include <nettle/dsa.h>
#include <nettle/rsa.h>
#include <nettle/ecc-curve.h>

namespace securepath::ssh::nettle {

class ed25519_public_key : public public_key {
public:
	ed25519_public_key(ed25519_public_key_data const& d)
	: pubkey_(d.pubkey.begin(), d.pubkey.end())
	{
	}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	bool verify(const_span msg, const_span signature) const override {
		if(signature.size() != ED25519_SIGNATURE_SIZE) {
			return false;
		}

		return nettle_ed25519_sha512_verify(
			to_uint8_ptr(pubkey_),
			msg.size(),
			to_uint8_ptr(msg),
			to_uint8_ptr(signature) ) == 1;
	}

	bool fill_data(public_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<ed25519_public_key_data&>(data);
			d.pubkey = const_span(pubkey_);
		}
		return ret;
	}

private:
	byte_vector pubkey_;
};


class rsa_public_key : public public_key {
public:
	rsa_public_key(rsa_public_key_data const& d)
	: e_(d.e.data.begin(), d.e.data.end())
	, n_(d.n.data.begin(), d.n.data.end())
	{
		nettle_rsa_public_key_init(&public_key_);
		nettle_mpz_set_str_256_u(public_key_.e, d.e.data.size(), to_uint8_ptr(d.e.data));
		nettle_mpz_set_str_256_u(public_key_.n, d.n.data.size(), to_uint8_ptr(d.n.data));
		is_valid_ = nettle_rsa_public_key_prepare(&public_key_) == 1;
	}

	~rsa_public_key() {
		nettle_rsa_public_key_clear(&public_key_);
	}

	bool valid() const {
		return is_valid_;
	}

	key_type type() const override {
		return key_type::ssh_rsa;
	}

	bool verify(const_span in, const_span signature) const override {
		mpz_t sig;
		nettle_mpz_init_set_str_256_u(sig, signature.size(), to_uint8_ptr(signature));

		sha1_ctx sha1;
		nettle_sha1_init(&sha1);
		sha1_update(&sha1, in.size(), to_uint8_ptr(in));

		bool res = nettle_rsa_sha1_verify(&public_key_, &sha1, sig) == 1;
		mpz_clear(sig);
 		return res;
	}

	bool fill_data(public_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<rsa_public_key_data&>(data);
			d.e.data = const_span(e_);
			d.n.data = const_span(n_);
		}
		return ret;
	}

private:
	bool is_valid_{};
	byte_vector e_;
	byte_vector n_;
	::rsa_public_key public_key_;
};


class ecdsa_public_key : public public_key {
public:
	ecdsa_public_key(ecdsa_public_key_data const& d, crypto_call_context const& call)
	: type_(d.ecdsa_type)
	, pubkey_(d.ecc_point.begin(), d.ecc_point.end())
	{
		ecc_point_init(&ecc_point_, nettle_get_secp_256r1());
		// see the size is correct and it is uncompressed ecc point, otherwise don't bother
		if(d.ecc_point.size() == 65 && d.ecc_point[0] == std::byte{0x04}) {
			mpz_t x, y;
			nettle_mpz_init_set_str_256_u(x, 32, to_uint8_ptr(d.ecc_point)+1);
			nettle_mpz_init_set_str_256_u(y, 32, to_uint8_ptr(d.ecc_point)+33);

			is_valid_ = nettle_ecc_point_set(&ecc_point_, x, y) == 1;
			mpz_clear(x);
			mpz_clear(y);
		}
	}

	~ecdsa_public_key() {
		ecc_point_clear(&ecc_point_);
	}

	bool valid() const {
		return is_valid_;
	}

	key_type type() const override {
		return type_;
	}

	bool verify(const_span msg, const_span signature) const override {
		if(signature.size() != 64) {
			return false;
		}

		dsa_signature sig;
		nettle_dsa_signature_init(&sig);
		nettle_mpz_set_str_256_u(sig.r, 32, to_uint8_ptr(signature));
		nettle_mpz_set_str_256_u(sig.s, 32, to_uint8_ptr(signature)+32);
		bool res = nettle_ecdsa_verify(&ecc_point_, msg.size(), to_uint8_ptr(msg), &sig) == 1;
		nettle_dsa_signature_clear(&sig);
		return res;
	}

	bool fill_data(public_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<ecdsa_public_key_data&>(data);
			d.ecc_point = const_span(pubkey_);
		}
		return ret;
	}

private:
	bool is_valid_{};
	key_type type_;
	byte_vector pubkey_;
	ecc_point ecc_point_;
};


std::shared_ptr<ssh::public_key> create_public_key(public_key_data const& d, crypto_call_context const& call) {
	if(d.type() == key_type::ssh_ed25519) {
		return std::make_shared<ed25519_public_key>(static_cast<ed25519_public_key_data const&>(d));
	} else if(d.type() == key_type::ssh_rsa) {
		auto key = std::make_shared<rsa_public_key>(static_cast<rsa_public_key_data const&>(d));
		if(key->valid()) {
			return key;
		}
	} else if(d.type() == key_type::ecdsa_sha2_nistp256) {
		auto key = std::make_shared<ecdsa_public_key>(static_cast<ecdsa_public_key_data const&>(d), call);
		if(key->valid()) {
			return key;
		}
	}
	return nullptr;
}

}

