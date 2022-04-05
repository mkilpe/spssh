
#include "log.hpp"
#include "test_buffers.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/core/ssh_public_key.hpp"
#include "ssh/core/ssh_private_key.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

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
};

// ssh-ed25519
std::string const ed25519_fprint = "SHA256:AJxI+SMrILxnTIinoWVeFhz3BGq9zH+VyOcH6IsJV/0";
std::string const ed25519_pubkey = "AAAAC3NzaC1lZDI1NTE5AAAAIKybvEDG+Tp2x91UjeDAFwmeOfitihW8fKN4rzMf2DBn";
std::string const ed25519_privkey = "AAAAC3NzaC1lZDI1NTE5AAAAIKybvEDG+Tp2x91UjeDAFwmeOfitihW8fKN4rzMf2DBnAAAAQEee9Mvoputz204F1EtY51yPsLFm10kpJOw1tMVVyZT2rJu8QMb5OnbH3VSN4MAXCZ45+K2KFbx8o3ivMx/YMGcAAAARbWlrYWVsQG1pa2FlbC1kZXYBAgME";

// ssh-rsa 2048 bits
std::string const rsa_fprint = "SHA256:5Z6Yec2hkGWPFAfuGcjn9RqZ1TOInBzu9omIyXpByZk";
std::string const rsa_pubkey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDRdy5ReJknJnltipRomk22yJ+tRmFH1oSYAq9Aa+j4TzAdMp0DzEb35dvyHSP6mjfg6Lptu/0E7JXV4xpF+saJzLZiiwyxEViDRygRKaPTQSoh1gIrX2p5PWr2w9Mw2CJVWxt33q/c9xBsRgvx5rkaQayVqdsGEsJ0t7y/jm9sPtkwVkvWMcTKzv/PRFDRmPeoozyE7defF6/4ag+7wkv7sVFPVTscZFzEyrKuQtSMxoAv4SZ03XugtMF29koqTrlZnhzBGKJdQ25cm2M2EkxBeXZG2/TbaWOf89vTMoxuR4wd+VAdk7YB7+P0X2T0MzQzXKFYJbNpLpcpiO9bcJwn";
std::string const rsa_privkey = "AAAAB3NzaC1yc2EAAAEBANF3LlF4mScmeW2KlGiaTbbIn61GYUfWhJgCr0Br6PhPMB0ynQPMRvfl2/IdI/qaN+Doum27/QTsldXjGkX6xonMtmKLDLERWINHKBEpo9NBKiHWAitfank9avbD0zDYIlVbG3fer9z3EGxGC/HmuRpBrJWp2wYSwnS3vL+Ob2w+2TBWS9YxxMrO/89EUNGY96ijPITt158Xr/hqD7vCS/uxUU9VOxxkXMTKsq5C1IzGgC/hJnTde6C0wXb2SipOuVmeHMEYol1DblybYzYSTEF5dkbb9NtpY5/z29MyjG5HjB35UB2TtgHv4/RfZPQzNDNcoVgls2kulymI71twnCcAAAADAQABAAABAEOs0+QyqJjDj3vayDQ7llw12ZEsKgYBwvkx9NlFhBGl1A+66IvvlgZF15gT3in7ZY5e4szNbeQHZCmkpDpz2W1wHIUeE82powVXGhThdTKt3STtden5e/cL5uEvR66CRiV5uBg0dHFZyY6R2w4e0zMugMoiBMeji/wV2P+yz0ETP3/OmJAtEzT538yPUTZcXhsrAHt7NYFRsyCPOp0/cAcjrvVza/0Hc0EQOXH4CQ1Z5wv8TT/mOl0iwypw+bpWrBMNraajoc2+aKoBaau0DL3SCKBBoyryywFQrE2nVuJnZ6srte+xqq3k5Q2eJqMydYez0pgNpJDF+VJhx20IDaEAAACAFaYIXLsJq7cgq/YJ/e5JgvFB3kOLM6JjgCBqIlC8u3SY/ItbsL8ABV1Q9uhYiBS0hfPVvyqKbn2DH5I28QGO28iZj4C6/iN+gw4e7dYmajLaXfMptiPFDRzlpiBZBvQal2RvyAlZPhvBmMyBECwZL5YnCuftjPIttil5XUoGG0QAAACBAO0Vru8K5QbuI/JKlqtT/RJNDqvFvl7rsLXHQmxh+GOod1CH6b7BFhEOXk3k33zuvS5z8/XdmOVgDAMtUIpuJHg8KR8E8/N49C46qo0NvtxO7mlsJcHudO7iwInzamnBESuTH66Ksiw0D39b3gSZexzKMwyd9PNbex1VYd7L4SwJAAAAgQDiLWR/pzoIh/NRufun43BEu0xFCBHKOzv6k2V0JPpHCJWldZaO5dGwkEwCfX3OwzbxePRCgZvBOqxFINpjWWgadB+NdehGUXt+/0PN2Z8Xz4tiIsRHbHWtfVfo4McKc2SiO+6hdcW54WtrgVNn7kew9KTZnoyUpPG3Md0AeIvyrwAAABFtaWthZWxAbWlrYWVsLWRldgEC";

// ecdsa-sha2-nistp256
std::string const ecdsa_fprint = "SHA256:ZmYg0OTL/fFyvbYYLS0cqhIS/DiYfedHrQsAnV+3BIg";
std::string const ecdsa_pubkey = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIEkoZ57E2A6B5+tkiq9NXww3Cccys8XLNRy5e8tzRByJwdTgyBA5mAgyP3gc62FUSV1bcfHo1xf5d3oG9V8TLA=";
std::string const ecdsa_privkey = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIEkoZ57E2A6B5+tkiq9NXww3Cccys8XLNRy5e8tzRByJwdTgyBA5mAgyP3gc62FUSV1bcfHo1xf5d3oG9V8TLAAAAAhAOnXZPTC1E5He4mnpR5yYZiOjtgNcXgM+rBwMmzRV/WSAAAAEW1pa2FlbEBtaWthZWwtZGV2AQIDBAUG";

struct {
	key_type type;
	std::string fprint;
	std::string pubkey;
	std::string privkey;
} const test_keys[] =
	{
		{key_type::ssh_ed25519, ed25519_fprint, ed25519_pubkey, ed25519_privkey},
		{key_type::ssh_rsa, rsa_fprint, rsa_pubkey, rsa_privkey},
		{key_type::ecdsa_sha2_nistp256, ecdsa_fprint, ecdsa_pubkey, ecdsa_privkey},
	};

std::size_t const test_key_count = sizeof(test_keys)/sizeof(*test_keys);


TEST_CASE("ed25519 public and private key", "[unit][crypto]") {
	crypto_test_context ctx;

	byte_vector gen_priv_key(ed25519_key_size);
	ctx.rand->random_bytes(gen_priv_key);

	ed25519_private_key_data data{ed25519_private_key_data::value_type(gen_priv_key.data(), gen_priv_key.size())};
	auto priv = ctx.construct_private_key(data, ctx.call);
	REQUIRE(priv);

	byte_vector msg(69, std::byte{'A'});
	auto sig = priv->sign(msg);
	REQUIRE(!sig.empty());

	auto pub = priv->public_key();
	REQUIRE(pub);

	CHECK(pub->verify(msg, sig));
}

TEST_CASE("ssh public key", "[unit][crypto]") {
	auto i = GENERATE(range(0ul, test_key_count));
	CAPTURE(i);

	crypto_test_context ctx;

	auto pub = load_base64_ssh_public_key(test_keys[i].pubkey, ctx, ctx.call);
	REQUIRE(pub.valid());

	CHECK(pub.type() == test_keys[i].type);
	CHECK(pub.fingerprint(ctx, ctx.call) == test_keys[i].fprint);
}

TEST_CASE("ssh private key", "[unit][crypto]") {
	auto i = GENERATE(range(0ul, test_key_count));
	CAPTURE(i);

	crypto_test_context ctx;

	auto priv = load_raw_base64_ssh_private_key(test_keys[i].privkey, ctx, ctx.call);
	REQUIRE(priv.valid());

	CHECK(priv.type() == test_keys[i].type);

	byte_vector msg(69, std::byte{'A'});
	auto sig = priv.sign(msg);
	REQUIRE(!sig.empty());

	{
		auto pub = priv.public_key();
		REQUIRE(pub.valid());

		CHECK(pub.verify(msg, sig));
	}
	{
		auto pub = load_base64_ssh_public_key(test_keys[i].pubkey, ctx, ctx.call);
		REQUIRE(pub.valid());

		CHECK(pub.verify(msg, sig));
	}
}

key_exchange_type const test_key_exchanges[] =
	{
		key_exchange_type::X25519
	};

std::size_t test_key_exchange_count = sizeof(test_key_exchanges)/sizeof(*test_key_exchanges);

TEST_CASE("x25519 key exchange", "[unit][crypto]") {
	auto i = GENERATE(range(0ul, test_key_exchange_count));

	CAPTURE(i);

	crypto_test_context ctx;

	auto exc1 = ctx.construct_key_exchange(test_key_exchanges[i], ctx.call);
	auto exc2 = ctx.construct_key_exchange(test_key_exchanges[i], ctx.call);

	REQUIRE(exc1);
	REQUIRE(exc2);

	auto secret1 = exc2->agree(exc1->public_key());
	auto secret2 = exc1->agree(exc2->public_key());

	CHECK(!secret1.empty());
	CHECK(secret1 == secret2);
}

}