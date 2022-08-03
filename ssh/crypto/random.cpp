#include "random.hpp"

#include "config.hpp"
#include "ssh/common/util.hpp"

#ifdef HAVE_GETENTROPY
#include <unistd.h>

static bool my_random(securepath::ssh::span output) {
	while(!output.empty()) {
		// max allowed size to call getentropy is 256
		std::size_t s = std::min<std::size_t>(output.size(), 256);
		if(::getentropy(output.data(), s) != 0) {
			return false;
		}
		output = securepath::ssh::safe_subspan(output, s);
	}
	return true;
}
#define USE_RANDOM

#elif defined(HAVE_GETRANDOM)
#include <sys/random.h>

static bool my_random(securepath::ssh::span output) {
	while(!output.empty()) {
		/*
			By default, getrandom() draws entropy from the /dev/urandom pool. This behavior can be
			changed via the flags argument. If the /dev/urandom pool has been initialized, reads of
			up to 256 bytes will always return as many bytes as requested and will not be interrupted
			by signals.
        */
		std::size_t s = std::min<std::size_t>(output.size(), 256);
		ssize_t res = ::get-random(output.data(), s, 0);
		if(res > 0) {
			output = securepath::ssh::safe_subspan(output, s);
		} else {
			return false;
		}
	}
	return true;
}
#define USE_RANDOM

#elif _WIN32
#include <wincrypt.h>

#error implement

static bool my_random(securepath::ssh::span output) {
	//use CryptGenRandom
	return false;
}
#define USE_RANDOM
#endif

#include <cstdio>
#include <limits>
#include <random>

namespace securepath::ssh {

#ifdef USE_RANDOM
namespace {

static void gen_random(span output) {
	if(!my_random(output)) {
		// cannot get random, nothing we can do...
		fprintf( stderr, "Could not generate random, aborting...");
		std::abort();
	}
}

struct rand_adaptor {
	using result_type = std::uint8_t;

    static constexpr result_type min() { return std::numeric_limits<result_type>::min(); }
	static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }

	result_type operator()() {
		std::byte res{};
		gen_random(span{&res, 1});
		return std::to_integer<std::uint8_t>(res);
	}
};

class def_random : public random {
public:
	std::size_t random_uint(std::size_t min, std::size_t max) override {
		rand_adaptor ra;
		std::uniform_int_distribution<std::size_t> uidist(min, max);
		return uidist(ra);
	}

	void random_bytes(span output) override {
		gen_random(output);
	}
};
}

std::unique_ptr<random> create_default_random() {
	return std::make_unique<def_random>();
}
#endif

}
