
#include "ssh/crypto/random.hpp"
#include <securepath/crypto/random.hpp>
#include <memory>

namespace securepath::ssh::nettle {

// since nettle doesn't provide random bytes, we use sp functions here
// consider how to get rid of the dependency
class random : public ssh::random {
public:

	// returns random std::size_t between [min, max] range
	std::size_t random_uint(std::size_t min, std::size_t max) override {
		return crypto::random_number(min, max);
	}

	// fills the given span with random bytes
	void random_bytes(span output) override {
		crypto::random_data(output.size(), reinterpret_cast<std::uint8_t*>(output.data()));
	}
};

std::unique_ptr<ssh::random> create_random() {
	return std::make_unique<random>();
}

}
