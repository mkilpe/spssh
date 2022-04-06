
#include "log.hpp"
#include "ssh/core/kexinit.hpp"
#include "ssh/core/supported_algorithms.hpp"
#include <external/catch/catch.hpp>

namespace securepath::ssh::test {
namespace {

supported_algorithms const t1
	{{kex_type::curve25519_sha256}
	,{key_type::ssh_ed25519}
	,{cipher_type::aes_256_gcm}
	,{cipher_type::aes_256_gcm}
	,{mac_type::aes_256_gcm}
	,{mac_type::aes_256_gcm}};

supported_algorithms const t1_1
	{{kex_type::curve25519_sha256}
	,{key_type::ssh_rsa, key_type::ssh_ed25519}
	,{cipher_type::aes_256_gcm}
	,{cipher_type::aes_256_gcm}
	,{mac_type::aes_256_gcm}
	,{mac_type::aes_256_gcm}};

supported_algorithms const t2
	{{kex_type::dh_group14_sha256}
	,{key_type::ssh_ed25519}
	,{cipher_type::aes_256_gcm}
	,{cipher_type::aes_256_gcm}
	,{mac_type::aes_256_gcm}
	,{mac_type::aes_256_gcm}};

supported_algorithms const t2_1
	{{kex_type::dh_group14_sha256, kex_type::curve25519_sha256, kex_type::ecdh_sha2_nistp256}
	,{key_type::ssh_rsa, key_type::ecdsa_sha2_nistp256, key_type::ssh_ed25519}
	,{cipher_type::aes_256_ctr, cipher_type::aes_256_gcm}
	,{cipher_type::aes_256_gcm, cipher_type::aes_256_ctr}
	,{mac_type::hmac_sha2_256, mac_type::aes_256_gcm}
	,{mac_type::aes_256_gcm, mac_type::hmac_sha2_256}};

supported_algorithms const t2_1_inv
	{{kex_type::ecdh_sha2_nistp256, kex_type::curve25519_sha256, kex_type::dh_group14_sha256 }
	,{key_type::ssh_ed25519, key_type::ecdsa_sha2_nistp256, key_type::ssh_rsa}
	,{cipher_type::aes_256_gcm, cipher_type::aes_256_ctr}
	,{cipher_type::aes_256_ctr, cipher_type::aes_256_gcm}
	,{mac_type::aes_256_gcm, mac_type::hmac_sha2_256}
	,{mac_type::hmac_sha2_256, mac_type::aes_256_gcm}};

supported_algorithms const t3
	{{kex_type::dh_group14_sha256}
	,{key_type::ssh_ed25519}
	,{cipher_type::aes_256_gcm}
	,{cipher_type::aes_256_gcm}
	,{mac_type::hmac_sha2_256}
	,{mac_type::aes_256_gcm}};

crypto_configuration const result1
	{kex_type::curve25519_sha256
	,key_type::ssh_ed25519
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}};

crypto_configuration const result2
	{kex_type::dh_group14_sha256
	,key_type::ssh_ed25519
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}};

crypto_configuration const result2_1
	{kex_type::dh_group14_sha256
	,key_type::ssh_rsa
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}
	,{cipher_type::aes_256_ctr, mac_type::hmac_sha2_256, compress_type::none}};

crypto_configuration const result2_inv_1
	{kex_type::ecdh_sha2_nistp256
	,key_type::ssh_ed25519
	,{cipher_type::aes_256_ctr, mac_type::hmac_sha2_256, compress_type::none}
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}};

crypto_configuration const result2_inv_2
	{kex_type::ecdh_sha2_nistp256
	,key_type::ssh_ed25519
	,{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}
	,{cipher_type::aes_256_ctr, mac_type::hmac_sha2_256, compress_type::none}};


struct test_config {
	transport_side my_side;
	supported_algorithms my_algos;
	supported_algorithms remote_algos;
	crypto_configuration result;
	bool correct_guess{};
};

test_config const test_configs[] =
	{
		{transport_side::client, t1, t1, result1, true},
		{transport_side::server, t1, t1, result1, true},
		{transport_side::client, t1, {}, {}},
		{transport_side::client, {}, t1, {}},
/*4*/	{transport_side::client, {}, {}, {}},
		{transport_side::server, t1, {}, {}},
		{transport_side::server, {}, t1, {}},
		{transport_side::server, {}, {}, {}},
		{transport_side::client, t1, t1_1, result1, true},
/*9*/	{transport_side::server, t1, t1_1, result1, true},
		{transport_side::client, t1_1, t1, result1, true},
		{transport_side::server, t1_1, t1, result1, true},
		{transport_side::client, t1, t2, {}},
		{transport_side::server, t1, t2, {}},
/*14*/	{transport_side::client, t2, t2_1, result2, true},
		{transport_side::server, t2, t2_1, result2, true},
		{transport_side::client, t2_1, t2, result2, true},
		{transport_side::server, t2_1, t2, result2, true},
		{transport_side::client, t2_1, t2_1, result2_1, true},
/*19*/	{transport_side::client, t2_1, t2_1_inv, result2_1, false},
		{transport_side::server, t2_1, t2_1_inv, result2_inv_2, false},
		{transport_side::client, t2_1_inv, t2_1_inv, result2_inv_1, true},
		{transport_side::server, t2_1_inv, t2_1_inv, result2_inv_2, true},
		{transport_side::client, t2, t3, {}},
/*24*/	{transport_side::server, t2, t3, {}},
		{transport_side::client, t3, t2, {}},
		{transport_side::server, t3, t2, {}}
	};

}

TEST_CASE("kexinit agreement", "[unit]") {
	auto i = GENERATE(range(0, int(sizeof(test_configs)/sizeof(test_config))));

	INFO("The test conf index is " << i);

	test_config const& conf = test_configs[i];

	kexinit_agreement kagree(test_log(), conf.my_side, conf.my_algos);
	if(conf.result.valid()) {
		REQUIRE(kagree.agree(conf.remote_algos));
		CHECK(kagree.was_guess_correct() == conf.correct_guess);
		CHECK(kagree.agreed_configuration() == conf.result);
	} else {
		REQUIRE(!kagree.agree(conf.remote_algos));
	}
}

}