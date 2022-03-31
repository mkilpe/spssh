#ifndef SP_SSH_CRYPTO_NETTLE_UTIL_HEADER
#define SP_SSH_CRYPTO_NETTLE_UTIL_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh::nettle {

inline void clamp25519(span key) {
	if(key.size() == 32) {
		// decode 32 random bytes as an integer scalar (RFC 7748)
		key[0]  &= std::byte{248};
		key[31] &= std::byte{127};
		key[31] |= std::byte{64};
	}
}

}

#endif
