#ifndef SP_SSH_CRYPTO_PRIVATE_KEY_HEADER
#define SP_SSH_CRYPTO_PRIVATE_KEY_HEADER

#include "ids.hpp"
#include <optional>

namespace securepath::ssh {

class public_key;

class private_key {
public:
	virtual ~private_key() = default;

	virtual key_type type() const = 0;
	virtual std::unique_ptr<ssh::public_key> public_key() const = 0;

	// sign data
	virtual std::size_t signature_size() const = 0;
	virtual bool sign(const_span in, span out) const = 0;

	std::vector<std::byte> sign(const_span in) const {
		std::vector<std::byte> res;
		res.resize(signature_size());
		if(sign(in, res)) {
			return res;
		}
		return {};
	}
};

struct private_key_data {
	virtual key_type type() const = 0;
protected:
	~private_key_data() = default;
};

struct ed25519_private_key_data : private_key_data {
	using value_type = std::span<std::byte const, ed25519_key_size>;

	ed25519_private_key_data(value_type priv, std::optional<value_type> pub = std::nullopt)
	: privkey(priv)
	, pubkey(pub)
	{}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	value_type privkey;
	std::optional<value_type> pubkey;
};

struct rsa_private_key_data : private_key_data {

	rsa_private_key_data(const_span e, const_span n, const_span d, const_span p, const_span q)
	: e(e), n(n), d(d), p(p), q(q)
	{
	}

	//Represents multiple precision integers in two's complement format,
	//stored as a string, 8 bits per byte, MSB first [RFC4251]
	const_span e;
	const_span n;
	const_span d;
	const_span p;
	const_span q;

	key_type type() const override {
		return key_type::ssh_rsa;
	}
};


struct ecdsa_private_key_data : private_key_data {

	ecdsa_private_key_data(std::string_view curve, const_span ecc_point, const_span privkey)
	: curve(curve)
	, ecc_point(ecc_point)
	, privkey(privkey)
	{
	}

	// curve name
	std::string_view curve;

	// the public key encoded from an elliptic curve point into an octet string (https://www.secg.org/sec1-v2.pdf)
	const_span ecc_point;
	const_span privkey;

	key_type type() const override {
		if(curve == "nistp256") {
			return key_type::ecdsa_sha2_nistp256;
		}
		return key_type::unknown;
	}
};


}

#endif
