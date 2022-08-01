#include "random.hpp"
/*
#ifdef __linux__
#include <unistd.h>
#include <linux/version.h>

#ifdef __GLIBC__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ > 24))
#include <sys/random.h>
#define HAS_GETRANDOM
#endif
#endif
#endif

namespace securepath::ssh {

class def_random {
public:
	std::size_t random_uint(std::size_t min, std::size_t max) override {

	}

	void random_bytes(span output) override {
#ifdef HAS_GETRANDOM
		// draws entropy from the urandom source
		if(::getrandom(output.data(), output.size(), 0)
#endif
	}
};

std::unique_ptr<random> default_random() {
	return std::make_unique<def_random>();
}

}
*/