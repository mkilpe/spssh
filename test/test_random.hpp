#ifndef SSH_TEST_RANDOM_HEADER
#define SSH_TEST_RANDOM_HEADER

#include "ssh/crypto/random.hpp"

#include <cstdlib>
#include <cstring>

namespace securepath::ssh::test {

class trandom : public random {
public:
	// returns random std::size_t between [min, max] range
	std::size_t random_uint(std::size_t min, std::size_t max) override {
		return min + (std::rand() % (max-min+1));
	}

	// fills the given span with random bytes
	void random_bytes(span output) override {
		std::memset(output.data(), 0, output.size());
	}
} test_rand;


}

#endif