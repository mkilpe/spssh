#ifndef SP_SSH_CRYPTO_CRYPTO_CONTEXT_HEADER
#define SP_SSH_CRYPTO_CRYPTO_CONTEXT_HEADER

#include "ids.hpp"
#include "crypto_call_context.hpp"
#include "cipher.hpp"
#include "compress.hpp"
#include "mac.hpp"
#include "public_key.hpp"
#include "key_exchange.hpp"

#include <functional>
#include <memory>

namespace securepath::ssh {

template<typename Algo, typename Impl>
using ctor = std::function<std::unique_ptr<Impl> (Algo, crypto_call_context const&)>;

/// Context that is used to construct all crypto objects
struct crypto_context {
	std::function<std::unique_ptr<random>()> construct_random{};

	ctor<cipher_type, cipher> construct_cipher{};
	ctor<mac_type, mac> construct_mac{};
	ctor<compress_type, compress> construct_compress{};
	ctor<key_type, public_key> construct_public_key{};
	ctor<key_exchange_type, key_exchange> construct_key_exchange{};
};

crypto_context default_crypto_context();

}

#endif
