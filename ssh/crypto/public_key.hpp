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

}

#endif
