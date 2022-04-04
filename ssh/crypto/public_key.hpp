#ifndef SP_SSH_CRYPTO_PUBLIC_KEY_HEADER
#define SP_SSH_CRYPTO_PUBLIC_KEY_HEADER

#include "ids.hpp"

namespace securepath::ssh {

class public_key {
public:
	virtual ~public_key() = default;

	virtual key_type type() const = 0;

	// verify data
	virtual bool verify(const_span msg, const_span signature) const = 0;
};

struct public_key_data {
	virtual key_type type() const = 0;
protected:
	~public_key_data() = default;
};

struct ed25519_public_key_data : public_key_data {
	using value_type = std::span<std::byte const, ed25519_key_size>;

	ed25519_public_key_data(value_type v)
	: pubkey(v)
	{}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	value_type pubkey;
};

struct rsa_public_key_data : public_key_data {
	rsa_public_key_data(const_span e, const_span n)
	: e(e)
	, n(n)
	{
	}

	//Represents multiple precision integers in two's complement format,
	//stored as a string, 8 bits per byte, MSB first [RFC4251]
	const_span e;
	const_span n;

	key_type type() const override {
		return key_type::ssh_rsa;
	}
};

struct ecdsa_public_key_data : public_key_data {
	ecdsa_public_key_data(std::string_view curve, const_span ecc_point)
	: curve(curve)
	, ecc_point(ecc_point)
	{
	}

	// curve name
	std::string_view curve;

	// the public key encoded from an elliptic curve point into an octet string (https://www.secg.org/sec1-v2.pdf)
	const_span ecc_point;

	key_type type() const override {
		if(curve == "nistp256") {
			return key_type::ecdsa_sha2_nistp256;
		}
		return key_type::unknown;
	}
};

}

#endif
