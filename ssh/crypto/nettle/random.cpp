
#include "ssh/crypto/random.hpp"

namespace securepath::ssh::nettle {

class random : public ssh::random {
public:

	// returns random std::size_t between [min, max] range
	std::size_t random_uint(std::size_t min, std::size_t max) override {

	}

	// fills the given span with random bytes
	void random_bytes(span output) override {

	}
};

}
