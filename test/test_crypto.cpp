
#include "log.hpp"
#include "test_buffers.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/core/ssh_public_key.hpp"
#include "ssh/core/ssh_private_key.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::ssh::test {

std::string const fprint1 = "SHA256:AJxI+SMrILxnTIinoWVeFhz3BGq9zH+VyOcH6IsJV/0";
std::string const pubkey1 = "AAAAC3NzaC1lZDI1NTE5AAAAIKybvEDG+Tp2x91UjeDAFwmeOfitihW8fKN4rzMf2DBn";
std::string const privkey1 = "AAAAC3NzaC1lZDI1NTE5AAAAIKybvEDG+Tp2x91UjeDAFwmeOfitihW8fKN4rzMf2DBnAAAAQEee9Mvoputz204F1EtY51yPsLFm10kpJOw1tMVVyZT2rJu8QMb5OnbH3VSN4MAXCZ45+K2KFbx8o3ivMx/YMGcAAAARbWlrYWVsQG1pa2FlbC1kZXYBAgME";

TEST_CASE("ed25519 public and private key", "[unit][crypto]") {
	crypto_context c = default_crypto_context();
	auto rand = c.construct_random();
	REQUIRE(rand);
	crypto_call_context call{test_log(), *rand};

	std::vector<std::byte> gen_priv_key(ed25519_key_size);
	rand->random_bytes(gen_priv_key);

	ed25519_private_key_data data{ed25519_private_key_data::value_type(gen_priv_key.data(), gen_priv_key.size())};
	auto priv = c.construct_private_key(data, call);
	REQUIRE(priv);

	std::vector<std::byte> msg(69, std::byte{'A'});
	auto sig = priv->sign(msg);
	REQUIRE(!sig.empty());

	auto pub = priv->public_key();
	REQUIRE(pub);

	CHECK(pub->verify(msg, sig));
}

TEST_CASE("ssh public key", "[unit][crypto]") {
	crypto_context c = default_crypto_context();
	auto rand = c.construct_random();
	REQUIRE(rand);
	crypto_call_context call{test_log(), *rand};

	auto pub = load_base64_ssh_public_key(pubkey1, c, call);
	REQUIRE(pub.valid());

	CHECK(pub.type() == key_type::ssh_ed25519);
}

TEST_CASE("ssh private key", "[unit][crypto]") {
	crypto_context c = default_crypto_context();
	auto rand = c.construct_random();
	REQUIRE(rand);
	crypto_call_context call{test_log(), *rand};

	auto priv = load_raw_base64_ssh_private_key(privkey1, c, call);
	REQUIRE(priv.valid());

	CHECK(priv.type() == key_type::ssh_ed25519);

	std::vector<std::byte> msg(69, std::byte{'A'});
	auto sig = priv.sign(msg);
	REQUIRE(!sig.empty());

	{
		auto pub = priv.public_key();
		REQUIRE(pub.valid());

		CHECK(pub.verify(msg, sig));
	}
	{
		auto pub = load_base64_ssh_public_key(pubkey1, c, call);
		REQUIRE(pub.valid());

		CHECK(pub.verify(msg, sig));
	}
}

}