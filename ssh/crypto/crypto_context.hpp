#ifndef SP_SSH_CRYPTO_CRYPTO_CONTEXT_HEADER
#define SP_SSH_CRYPTO_CRYPTO_CONTEXT_HEADER

#include "ids.hpp"
#include "crypto_call_context.hpp"
#include "cipher.hpp"
#include "compress.hpp"
#include "mac.hpp"
#include "public_key.hpp"
#include "private_key.hpp"
#include "key_exchange.hpp"

#include <functional>
#include <memory>

namespace securepath::ssh {

template<typename Impl, typename... ExtraParams>
using ctor = std::function<std::unique_ptr<Impl> (ExtraParams const&..., crypto_call_context const&)>;

/// Context that is used to construct all crypto objects
struct crypto_context {
	std::function<std::unique_ptr<random>()> construct_random{};

	ctor<cipher, cipher_type> construct_cipher{};
	ctor<mac, mac_type> construct_mac{};
	ctor<compress, compress_type> construct_compress{};
	ctor<public_key, public_key_data> construct_public_key{};
	ctor<private_key, private_key_data> construct_private_key{};
	ctor<key_exchange, key_exchange_type> construct_key_exchange{};
};

crypto_context default_crypto_context();

}

#endif
