#ifndef SP_SSH_CRYPTO_PRIVATE_KEY_HEADER
#define SP_SSH_CRYPTO_PRIVATE_KEY_HEADER

#include "ids.hpp"

namespace securepath::ssh {

class private_key {
public:
	virtual ~private_key() = default;

	virtual key_type type() const = 0;
	// sign data
};

}

#endif
