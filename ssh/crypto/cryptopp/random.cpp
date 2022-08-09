
#include "random.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/random.hpp"
#include <memory>

namespace securepath::ssh::cryptopp {

random_gen& random_generator() {
	static thread_local random_gen rng;
	return rng;
}

struct rand_adaptor {
	using result_type = std::uint32_t;

    static constexpr result_type min() { return std::numeric_limits<result_type>::min(); }
	static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }

	result_type operator()() {
		return random_generator().GenerateWord32();
	}
};

class random : public ssh::random {
public:
	std::size_t random_uint(std::size_t min, std::size_t max) override {
		rand_adaptor ra;
		std::uniform_int_distribution<std::size_t> uidist(min, max);
		return uidist(ra);
	}

	void random_bytes(span output) override {
		random_generator().GenerateBlock(to_uint8_ptr(output), output.size());
	}
};

std::unique_ptr<random> create_random() {
	try {
		return std::make_unique<random>();
	} catch(CryptoPP::Exception const& ex) {
		// cannot get random, nothing we can do...
		fprintf( stderr, "Could not construct cryptopp random, aborting...");
		std::abort();
	}
	return nullptr;
}

}
