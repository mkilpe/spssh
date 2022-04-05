#ifndef SP_SSH_CRYPTO_PUBLIC_KEY_HEADER
#define SP_SSH_CRYPTO_PUBLIC_KEY_HEADER

#include "ids.hpp"

namespace securepath::ssh {

struct public_key_data {
	virtual key_type type() const = 0;
protected:
	~public_key_data() = default;
};

class public_key {
public:
	virtual ~public_key() = default;

	virtual key_type type() const = 0;

	// verify data
	virtual bool verify(const_span msg, const_span signature) const = 0;

	// the data must point to the same type as the public key
	virtual bool fill_data(public_key_data& data) const = 0;
};

struct ed25519_public_key_data : public_key_data {
	ed25519_public_key_data() = default;
	ed25519_public_key_data(const_span v)
	: pubkey(v)
	{}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	const_span pubkey;
};

struct rsa_public_key_data : public_key_data {
	rsa_public_key_data() = default;
	rsa_public_key_data(const_mpint_span e, const_mpint_span n)
	: e(e)
	, n(n)
	{
	}

	const_mpint_span e;
	const_mpint_span n;

	key_type type() const override {
		return key_type::ssh_rsa;
	}
};

struct ecdsa_public_key_data : public_key_data {
	ecdsa_public_key_data(key_type t, const_span ecc_point = {})
	: ecdsa_type(t)
	, ecc_point(ecc_point)
	{
	}

	key_type ecdsa_type;

	// the public key encoded from an elliptic curve point into an octet string (https://www.secg.org/sec1-v2.pdf)
	const_span ecc_point;

	key_type type() const override {
		return ecdsa_type;
	}
};

}

#endif
