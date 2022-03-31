#ifndef SP_SSH_CRYPTO_CRYPTO_CONTEXT_HEADER
#define SP_SSH_CRYPTO_CRYPTO_CONTEXT_HEADER

#include "ids.hpp"
#include "crypto_call_context.hpp"
#include "cipher.hpp"
#include "mac.hpp"
#include "public_key.hpp"
#include "private_key.hpp"
#include "key_exchange.hpp"
#include "hash.hpp"

#include <functional>
#include <memory>

namespace securepath::ssh {

template<typename Impl, typename... ExtraParams>
using ctor = std::function<std::unique_ptr<Impl> (ExtraParams const&..., crypto_call_context const&)>;

/// Context that is used to construct all crypto objects
struct crypto_context {

	/// construct random number generator suitable for cryptographic usage
	std::function<std::unique_ptr<random>()> construct_random{};

	/// construct cipher from type and secret key
	ctor<cipher, cipher_type, const_span, cipher_dir> construct_cipher{};
	/// construct mac from type and secret key
	ctor<mac, mac_type, const_span> construct_mac{};
	/// construct public key from public key data (derived class to give the data which has the key type, the data is copied)
	ctor<public_key, public_key_data> construct_public_key{};
	/// construct private key from private key data (derived class to give the data which has the key type, the data is copied)
	ctor<private_key, private_key_data> construct_private_key{};
	/// construct cryptographic key exchange/agreement algorithm
	ctor<key_exchange, key_exchange_type> construct_key_exchange{};
	/// construct hash algorithm
	ctor<hash, hash_type> construct_hash{};
};

crypto_context default_crypto_context();

}

#endif
