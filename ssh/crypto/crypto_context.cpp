
#include "crypto_context.hpp"

#include "config.hpp"
#ifdef USE_NETTLE
#	include "ssh/crypto/nettle/crypto_context.hpp"
#elif defined(USE_CRYPTOPP)
#	include "ssh/crypto/cryptopp/crypto_context.hpp"
#endif

namespace securepath::ssh {

crypto_context default_crypto_context() {
#ifdef USE_NETTLE
	return nettle::create_nettle_context();
#elif defined(USE_CRYPTOPP)
	return cryptopp::create_cryptopp_context();
#else
#	error No default crypto context set
#endif
	return crypto_context{};
}

}
