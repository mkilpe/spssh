#ifndef SP_SSH_CRYPTO_PRIVATE_KEY_HEADER
#define SP_SSH_CRYPTO_PRIVATE_KEY_HEADER

#include "ids.hpp"
#include <optional>

namespace securepath::ssh {

class public_key;

struct private_key_data {
	virtual key_type type() const = 0;
protected:
	~private_key_data() = default;
};

class private_key {
public:
	virtual ~private_key() = default;

	virtual key_type type() const = 0;
	virtual std::shared_ptr<ssh::public_key> public_key() const = 0;

	// sign data
	virtual std::size_t signature_size() const = 0;
	virtual bool sign(const_span in, span out) const = 0;

	byte_vector sign(const_span in) const {
		byte_vector res;
		res.resize(signature_size());
		if(sign(in, res)) {
			return res;
		}
		return {};
	}

	// the data must point to the same type as the public key
	virtual bool fill_data(private_key_data& data) const = 0;
};

struct ed25519_private_key_data : private_key_data {
	ed25519_private_key_data() = default;
	ed25519_private_key_data(const_span priv, std::optional<const_span> pub = std::nullopt)
	: privkey(priv)
	, pubkey(pub)
	{}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	const_span privkey;
	std::optional<const_span> pubkey;
};

struct rsa_private_key_data : private_key_data {
	rsa_private_key_data() = default;
	rsa_private_key_data(const_mpint_span e, const_mpint_span n, const_mpint_span d, const_mpint_span p, const_mpint_span q, const_mpint_span iqmp)
	: e(e), n(n), d(d), p(p), q(q), iqmp(iqmp)
	{
	}

	const_mpint_span e;
	const_mpint_span n;
	const_mpint_span d;
	const_mpint_span p;
	const_mpint_span q;
	// this can be empty, just for optimisation (inverse of q modulo p)
	const_mpint_span iqmp;

	key_type type() const override {
		return key_type::ssh_rsa;
	}
};


struct ecdsa_private_key_data : private_key_data {
	ecdsa_private_key_data() = default;
	ecdsa_private_key_data(key_type t, const_span ecc_point = {}, const_mpint_span privkey = {})
	: ecdsa_type(t)
	, ecc_point(ecc_point)
	, privkey(privkey)
	{
	}

	key_type ecdsa_type{};

	// the public key encoded from an elliptic curve point into an octet string (https://www.secg.org/sec1-v2.pdf)
	const_span ecc_point;
	const_mpint_span privkey;

	key_type type() const override {
		return ecdsa_type;
	}
};

struct private_key_info {
	key_type type{};
	// type specific size of the private key (bits for RSA, could be bytes for something else)
	// this might be ignored if there is only single size for the type (for example ed25519)
	std::size_t size{};
};

}

#endif
