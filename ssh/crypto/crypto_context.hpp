#ifndef SP_SSH_CRYPTO_CRYPTO_CONTEXT_HEADER
#define SP_SSH_CRYPTO_CRYPTO_CONTEXT_HEADER

#include "ids.hpp"
#include "crypto_call_context.hpp"

namespace securepath::ssh {

class cipher;
class mac;
class compress;
class public_key;

template<typename Algo, typename Impl>
using ctor = std::function<std::unique_ptr<Impl> (Algo, crypto_call_context const&)>;

/// Context that is used to construct all crypto objects
struct crypto_context {
	random& rand;
	ctor<cipher_type, cipher> construct_cipher{};
	ctor<mac_type, mac> construct_mac{};
	ctor<compress_type, compress> construct_compress{};
	ctor<key_type, public_key> construct_public_key{};
};

}

#endif
