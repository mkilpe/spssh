
#include "crypto_context.hpp"
#ifdef SPSSH_USE_NETTLE
#include "ssh/crypto/nettle/crypto_context.hpp"
#endif

namespace securepath::ssh {

crypto_context default_crypto_context() {
#ifdef SPSSH_USE_NETTLE
	return nettle::create_nettle_context();
#else
#error No default crypto context set
#endif
	return crypto_context{};
}

}
