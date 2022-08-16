
#include "nettle_helper.hpp"
#include "util.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/ids.hpp"

#include <memory>

#include <nettle/bignum.h>
#include <nettle/ecdsa.h>
#include <nettle/eddsa.h>
#include <nettle/dsa.h>
#include <nettle/rsa.h>
#include <nettle/sha1.h>
#include <nettle/ecc-curve.h>

namespace securepath::ssh::nettle {

std::shared_ptr<ssh::public_key> create_public_key(public_key_data const&, crypto_call_context const&);

class ed25519_private_key : public private_key {
public:
	ed25519_private_key(ed25519_private_key_data const& d, crypto_call_context call)
	: privkey_(d.privkey.begin(), d.privkey.end())
	, call_(call)
	{
		if(d.pubkey) {
			pubkey_.insert(pubkey_.end(), d.pubkey->begin(), d.pubkey->end());
		} else {
			pubkey_.resize(ed25519_key_size);
			nettle_ed25519_sha512_public_key(to_uint8_ptr(pubkey_), to_uint8_ptr(privkey_));
		}
	}

	ed25519_private_key(private_key_info const&, crypto_call_context call)
	: call_(call)
	{
		privkey_.resize(ed25519_key_size);
		pubkey_.resize(ed25519_key_size);
		call.rand.random_bytes(privkey_);
		clamp25519(privkey_);
		nettle_ed25519_sha512_public_key(to_uint8_ptr(pubkey_), to_uint8_ptr(privkey_));
	}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	std::shared_ptr<ssh::public_key> public_key() const override {
		ed25519_public_key_data data{pubkey_};
		return create_public_key(data, call_);
	}

	std::size_t signature_size() const override {
		return ED25519_SIGNATURE_SIZE;
	}

	bool sign(const_span in, span out) const override {
		SPSSH_ASSERT(out.size() >= ED25519_SIGNATURE_SIZE, "not enough size for signature");

		nettle_ed25519_sha512_sign(
			to_uint8_ptr(pubkey_),
			to_uint8_ptr(privkey_),
			in.size(),
			to_uint8_ptr(in),
			to_uint8_ptr(out) );

		return true;
	}

	bool fill_data(private_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<ed25519_private_key_data&>(data);
			d.privkey = privkey_;
			d.pubkey = pubkey_;
		}
		return ret;
	}

private:
	byte_vector pubkey_;
	byte_vector privkey_;
	crypto_call_context call_;
};

static void extract_rand(void *ctx, size_t length, uint8_t *dst) {
	random& r = *(random*)ctx;
	r.random_bytes(span((std::byte*)dst, length));
}

class rsa_private_key : public private_key {
public:
	rsa_private_key(rsa_private_key_data const& d, crypto_call_context const& call)
	: call_(call)
	, e_(d.e.data.begin(), d.e.data.end())
	, n_(d.n.data.begin(), d.n.data.end())
	, d_(d.d.data.begin(), d.d.data.end())
	, p_(d.p.data.begin(), d.p.data.end())
	, q_(d.q.data.begin(), d.q.data.end())
	{
		nettle_rsa_public_key_init(&public_key_);
		nettle_mpz_set_str_256_u(public_key_.e, d.e.data.size(), to_uint8_ptr(d.e.data));
		nettle_mpz_set_str_256_u(public_key_.n, d.n.data.size(), to_uint8_ptr(d.n.data));

		nettle_rsa_private_key_init(&key_);

		nettle_mpz_set_str_256_u(key_.d, d.d.data.size(), to_uint8_ptr(d.d.data));
		nettle_mpz_set_str_256_u(key_.p, d.p.data.size(), to_uint8_ptr(d.p.data));
		nettle_mpz_set_str_256_u(key_.q, d.q.data.size(), to_uint8_ptr(d.q.data));

		integer p_1, q_1;

		// calculate missing members
		mpz_sub_ui(p_1, key_.p, 1);
		mpz_sub_ui(q_1, key_.q, 1);
		mpz_mod(key_.a, key_.d, p_1);
		mpz_mod(key_.b, key_.d, q_1);

		is_valid_ = mpz_invert(key_.c, key_.q, key_.p) != 0
			&& nettle_rsa_public_key_prepare(&public_key_) == 1
			&& nettle_rsa_private_key_prepare(&key_) == 1;
	}

	rsa_private_key(private_key_info const& info, crypto_call_context const& call)
	: call_(call)
	{
		nettle_rsa_public_key_init(&public_key_);
		nettle_rsa_private_key_init(&key_);
		// we use fixed 65537 as e
		mpz_set_ui(public_key_.e, 65537);
		is_valid_ = nettle_rsa_generate_keypair(&public_key_, &key_, &call_.rand, extract_rand, nullptr, nullptr, info.size, 0) == 1;
		if(is_valid_) {
			e_.resize(nettle_mpz_sizeinbase_256_u(public_key_.e));
			nettle_mpz_get_str_256(e_.size(), to_uint8_ptr(e_), public_key_.e);

			n_.resize(nettle_mpz_sizeinbase_256_u(public_key_.n));
			nettle_mpz_get_str_256(n_.size(), to_uint8_ptr(n_), public_key_.n);

			d_.resize(nettle_mpz_sizeinbase_256_u(key_.d));
			nettle_mpz_get_str_256(d_.size(), to_uint8_ptr(d_), key_.d);

			p_.resize(nettle_mpz_sizeinbase_256_u(key_.p));
			nettle_mpz_get_str_256(p_.size(), to_uint8_ptr(p_), key_.p);

			q_.resize(nettle_mpz_sizeinbase_256_u(key_.q));
			nettle_mpz_get_str_256(q_.size(), to_uint8_ptr(q_), key_.q);
		}
	}

	~rsa_private_key() {
		nettle_rsa_private_key_clear(&key_);
		nettle_rsa_public_key_clear(&public_key_);
	}

	bool valid() const {
		return is_valid_;
	}

	key_type type() const override {
		return key_type::ssh_rsa;
	}

	std::shared_ptr<ssh::public_key> public_key() const override {
		rsa_public_key_data data{to_umpint(e_), to_umpint(n_)};
		return create_public_key(data, call_);
	}

	std::size_t signature_size() const override {
		return public_key_.size;
	}

	bool sign(const_span in, span out) const override {
		SPSSH_ASSERT(out.size() >= signature_size(), "not enough size for signature");

		integer sig;

		sha1_ctx sha1;
		nettle_sha1_init(&sha1);
		sha1_update(&sha1, in.size(), to_uint8_ptr(in));

		bool res = nettle_rsa_sha1_sign_tr(&public_key_, &key_, &call_.rand, extract_rand, &sha1, sig) == 1;
		if(res) {
			std::size_t size = nettle_mpz_sizeinbase_256_u(sig);
			SPSSH_ASSERT(out.size() >= size, "not enough size for signature");

			// notice that in PKCS#1 padding scheme the signature is always same size,
			// so we pad zeroes in front in case out integer is not big enough (as per PKCS#1 I2OSP)
			std::size_t padding = signature_size()-size;
			if(padding) {
				std::memset(out.data(), 0, padding);
			}
			nettle_mpz_get_str_256(size, to_uint8_ptr(out)+padding, sig);
		}
		return res;
	}

	bool fill_data(private_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<rsa_private_key_data&>(data);
			d.e.data = const_span(e_);
			d.n.data = const_span(n_);
			d.d.data = const_span(d_);
			d.p.data = const_span(p_);
			d.q.data = const_span(q_);
		}
		return ret;
	}

private:
	crypto_call_context call_;
	bool is_valid_{};
	::rsa_public_key public_key_;
	::rsa_private_key key_;

	// these are kept for fill_data and constructing public key
	byte_vector e_;
	byte_vector n_;
	byte_vector d_;
	byte_vector p_;
	byte_vector q_;
};


class ecdsa_private_key : public private_key {
public:
	ecdsa_private_key(ecdsa_private_key_data const& d, crypto_call_context const& call)
	: call_(call)
	, type_(d.ecdsa_type)
	, ecc_point_(d.ecc_point.begin(), d.ecc_point.end())
	, priv_key_(d.privkey.data.begin(), d.privkey.data.end())
	{
		nettle_ecc_scalar_init(&key_, nettle_get_secp_256r1());

		if(d.privkey.data.size() == 32 && d.ecc_point.size() == 65 && d.ecc_point[0] == std::byte{0x04}) {
			integer z(d.privkey.data);
			is_valid_ = nettle_ecc_scalar_set(&key_, z) == 1;
		}
	}

	ecdsa_private_key(private_key_info const& info, crypto_call_context const& call)
	: call_(call)
	, is_valid_(true)
	, type_(info.type)
	{
		ecc_point pub;
		nettle_ecc_scalar_init(&key_, nettle_get_secp_256r1());
		nettle_ecc_point_init(&pub, nettle_get_secp_256r1());

		ecdsa_generate_keypair(&pub, &key_, &call_.rand, extract_rand);

		ecc_point_.resize(65);
		ecc_point_[0] = std::byte{0x04};

		integer x, y, p;

		nettle_ecc_point_get(&pub, x, y);
		nettle_mpz_get_str_256(32, to_uint8_ptr(ecc_point_)+1, x);
		nettle_mpz_get_str_256(32, to_uint8_ptr(ecc_point_)+33, y);

		nettle_ecc_scalar_get(&key_, p);
		priv_key_.resize(32);
		nettle_mpz_get_str_256(32, to_uint8_ptr(priv_key_), p);

		ecc_point_clear(&pub);
	}

	~ecdsa_private_key() {
		nettle_ecc_scalar_clear(&key_);
	}

	bool valid() const {
		return is_valid_;
	}

	key_type type() const override {
		return type_;
	}

	std::shared_ptr<ssh::public_key> public_key() const override {
		ecdsa_public_key_data data{type_, ecc_point_};
		return create_public_key(data, call_);
	}

	std::size_t signature_size() const override {
		return 64;
	}

	bool sign(const_span in, span out) const override {
		SPSSH_ASSERT(out.size() >= signature_size(), "not enough size for signature");

		dsa_signature sig;
		nettle_dsa_signature_init(&sig);

		nettle_ecdsa_sign(&key_, &call_.rand, extract_rand, in.size(), to_uint8_ptr(in), &sig);
		nettle_mpz_get_str_256(32, to_uint8_ptr(out), sig.r);
		nettle_mpz_get_str_256(32, to_uint8_ptr(out)+32, sig.s);

		nettle_dsa_signature_clear(&sig);
		return true;
	}

	bool fill_data(private_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<ecdsa_private_key_data&>(data);
			d.ecdsa_type = type_;
			d.ecc_point = ecc_point_;
			d.privkey.data = const_span(priv_key_);
		}
		return ret;
	}

private:
	crypto_call_context call_;
	bool is_valid_{};
	key_type type_;
	ecc_scalar key_;
	byte_vector ecc_point_;
	byte_vector priv_key_;
};


std::shared_ptr<ssh::private_key> create_private_key(private_key_data const& d, crypto_call_context const& call) {
	if(d.type() == key_type::ssh_ed25519) {
		return std::make_shared<ed25519_private_key>(static_cast<ed25519_private_key_data const&>(d), call);
	} else if(d.type() == key_type::ssh_rsa) {
		auto key = std::make_shared<rsa_private_key>(static_cast<rsa_private_key_data const&>(d), call);
		if(key->valid()) {
			return key;
		}
	} else if(d.type() == key_type::ecdsa_sha2_nistp256) {
		auto key = std::make_shared<ecdsa_private_key>(static_cast<ecdsa_private_key_data const&>(d), call);
		if(key->valid()) {
			return key;
		}
	}
	return nullptr;
}

std::shared_ptr<ssh::private_key> generate_private_key(private_key_info const& info, crypto_call_context const& call) {
	if(info.type == key_type::ssh_ed25519) {
		return std::make_shared<ed25519_private_key>(info, call);
	} else if(info.type == key_type::ssh_rsa) {
		auto key = std::make_shared<rsa_private_key>(info, call);
		if(key->valid()) {
			return key;
		}
	} else if(info.type == key_type::ecdsa_sha2_nistp256) {
		auto key = std::make_shared<ecdsa_private_key>(info, call);
		if(key->valid()) {
			return key;
		}
	}
	return nullptr;
}

}
