#include "log.hpp"
#include "ssh/core/kexinit.hpp"
#include "ssh/core/supported_algorithms.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::ssh::test {

supported_algorithms const t1
	{{kex_type::curve25519_sha256}
	,{key_type::ssh_ed25519}
	,{cipher_type::aes_256_gcm}
	,{cipher_type::aes_256_gcm}
	,{mac_type::aes_256_gcm}
	,{mac_type::aes_256_gcm}};

crypto_configuration const t1_result
	{kex_type::curve25519_sha256
	,key_type::ssh_ed25519
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}};

TEST_CASE("kexinit agreement", "[unit]") {
	kexinit_agreement kagree(test_log(), transport_side::client, t1);
	REQUIRE(kagree.agree(t1));
	CHECK(kagree.was_guess_correct());
	CHECK(kagree.agreed_configuration() == t1_result);
}

}