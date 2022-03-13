#ifndef SP_SSH_CRYPTO_PUBLIC_KEY_HEADER
#define SP_SSH_CRYPTO_PUBLIC_KEY_HEADER

#include "ids.hpp"

namespace securepath::ssh {

class public_key {
public:
	virtual ~public_key() = default;

	virtual key_type type() const = 0;
	// verify data
};

}

#endif
