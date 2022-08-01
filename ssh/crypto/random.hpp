#ifndef SP_SSH_CRYPTO_RANDOM_HEADER
#define SP_SSH_CRYPTO_RANDOM_HEADER

#include "ssh/common/types.hpp"
#include <memory>

namespace securepath::ssh {

/// Interface to get random values/bytes
class random {
public:
	virtual ~random() = default;

	// returns random std::size_t between [min, max] range
	virtual std::size_t random_uint(std::size_t min, std::size_t max) = 0;

	// fills the given span with random bytes
	virtual void random_bytes(span output) = 0;
};

std::unique_ptr<random> default_random();

}

#endif
