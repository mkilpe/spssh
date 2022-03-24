#ifndef SP_SSH_CRYPTO_CRYPTO_CALL_CONTEXT_HEADER
#define SP_SSH_CRYPTO_CRYPTO_CALL_CONTEXT_HEADER

#include "random.hpp"
#include "ssh/common/types.hpp"
#include "ssh/common/logger.hpp"

namespace securepath::ssh {

/// Context that is passed to crypto construct functions
struct crypto_call_context {
	logger& log;
	random& rand;
};

}

#endif
