#ifndef SP_SSH_CRYPTO_KEY_EXCHANGE_HEADER
#define SP_SSH_CRYPTO_KEY_EXCHANGE_HEADER

#include "ssh/common/types.hpp"
#include <vector>

namespace securepath::ssh {

class key_exchange {
public:
	virtual ~key_exchange() = default;

	virtual key_exchange_type type() const = 0;

	/// return the public key part that is exchanged with the remote side (the format depends on the key exchange used)
	virtual const_span public_key() const = 0;

	/// calculate shared secret and return it
	virtual byte_vector agree(const_span remote_public) = 0;
};

struct key_exchange_data {
	virtual key_exchange_type type() const = 0;
protected:
	~key_exchange_data() = default;
};

struct x25519_key_exchange_data : key_exchange_data {
	key_exchange_type type() const override {
		return key_exchange_type::X25519;
	}
};

}

#endif
