#ifndef SP_SSH_CRYPTO_NETTLE_CRYPTO_CONTEXT_HEADER
#define SP_SSH_CRYPTO_NETTLE_CRYPTO_CONTEXT_HEADER

#include "ssh/crypto/crypto_context.hpp"

namespace securepath::ssh::nettle {

crypto_context create_nettle_context();

}

#endif
