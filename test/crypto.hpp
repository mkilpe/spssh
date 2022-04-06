
#ifndef SP_SSH_TEST_CRYPTO_HEADER
#define SP_SSH_TEST_CRYPTO_HEADER

#include "log.hpp"
#include "ssh/crypto/crypto_context.hpp"
#include "ssh/core/ssh_private_key.hpp"
#include <external/catch/catch.hpp>

namespace securepath::ssh::test {

struct crypto_test_context : crypto_context {
	crypto_test_context()
	: crypto_context(default_crypto_context())
	, rand(construct_random())
	, call(test_log(), *rand)
	{
		REQUIRE(rand);
	}

	std::unique_ptr<random> rand;
	crypto_call_context call;

public:
	ssh_private_key test_ed25519_private_key() const;
};

}

#endif
