#ifndef SP_SSH_CRYPTO_CRYPTO_CALL_CONTEXT_HEADER
#define SP_SSH_CRYPTO_CRYPTO_CALL_CONTEXT_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

class random;

/// Context that is passed to crypto construct functions
struct crypto_call_context {
	logger& log;
	random& rand;
};

}

#endif
