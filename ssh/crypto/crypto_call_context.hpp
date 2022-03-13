#ifndef SP_SSH_CRYPTO_CRYPTO_CALL_CONTEXT_HEADER
#define SP_SSH_CRYPTO_CRYPTO_CALL_CONTEXT_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh {

/// Context that is passed to crypto construct functions
class crypto_call_context {
public:
	logger& log;
};

}

#endif
