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
	virtual void sign(const_span in, const_span out) const = 0;

	std::vector<std::byte> sign(const_span in) const {
		std::vector<std::byte> res;
		res.resize(signature_size());
		sign(in, res);
		return res;
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

}

#endif
