
#include "crypto.hpp"
#include "test_buffers.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/core/ssh_public_key.hpp"
#include "ssh/core/ssh_private_key.hpp"

namespace securepath::ssh::test {

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

	ed25519_private_key_data data{const_span(gen_priv_key.data(), gen_priv_key.size())};
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

struct {
	key_type type;
	std::string fprint;
	std::string privkey;
} const openssh_test_keys[] =
	{
		{key_type::ssh_ed25519, ed25519_fprint,
R"**(-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCsm7xAxvk6dsfdVI3gwBcJnjn4rYoVvHyjeK8zH9gwZwAAAJhCwi2OQsIt
jgAAAAtzc2gtZWQyNTUxOQAAACCsm7xAxvk6dsfdVI3gwBcJnjn4rYoVvHyjeK8zH9gwZw
AAAEBHnvTL6Kbrc9tOBdRLWOdcj7CxZtdJKSTsNbTFVcmU9qybvEDG+Tp2x91UjeDAFwme
OfitihW8fKN4rzMf2DBnAAAAEW1pa2FlbEBtaWthZWwtZGV2AQIDBA==
-----END OPENSSH PRIVATE KEY-----
)**"},
		{key_type::ssh_rsa, rsa_fprint,
R"**(-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA0XcuUXiZJyZ5bYqUaJpNtsifrUZhR9aEmAKvQGvo+E8wHTKdA8xG
9+Xb8h0j+po34Oi6bbv9BOyV1eMaRfrGicy2YosMsRFYg0coESmj00EqIdYCK19qeT1q9s
PTMNgiVVsbd96v3PcQbEYL8ea5GkGslanbBhLCdLe8v45vbD7ZMFZL1jHEys7/z0RQ0Zj3
qKM8hO3Xnxev+GoPu8JL+7FRT1U7HGRcxMqyrkLUjMaAL+EmdN17oLTBdvZKKk65WZ4cwR
iiXUNuXJtjNhJMQXl2Rtv022ljn/Pb0zKMbkeMHflQHZO2Ae/j9F9k9DM0M1yhWCWzaS6X
KYjvW3CcJwAAA8jpgCQJ6YAkCQAAAAdzc2gtcnNhAAABAQDRdy5ReJknJnltipRomk22yJ
+tRmFH1oSYAq9Aa+j4TzAdMp0DzEb35dvyHSP6mjfg6Lptu/0E7JXV4xpF+saJzLZiiwyx
EViDRygRKaPTQSoh1gIrX2p5PWr2w9Mw2CJVWxt33q/c9xBsRgvx5rkaQayVqdsGEsJ0t7
y/jm9sPtkwVkvWMcTKzv/PRFDRmPeoozyE7defF6/4ag+7wkv7sVFPVTscZFzEyrKuQtSM
xoAv4SZ03XugtMF29koqTrlZnhzBGKJdQ25cm2M2EkxBeXZG2/TbaWOf89vTMoxuR4wd+V
Adk7YB7+P0X2T0MzQzXKFYJbNpLpcpiO9bcJwnAAAAAwEAAQAAAQBDrNPkMqiYw4972sg0
O5ZcNdmRLCoGAcL5MfTZRYQRpdQPuuiL75YGRdeYE94p+2WOXuLMzW3kB2QppKQ6c9ltcB
yFHhPNqaMFVxoU4XUyrd0k7XXp+Xv3C+bhL0eugkYlebgYNHRxWcmOkdsOHtMzLoDKIgTH
o4v8Fdj/ss9BEz9/zpiQLRM0+d/Mj1E2XF4bKwB7ezWBUbMgjzqdP3AHI671c2v9B3NBED
lx+AkNWecL/E0/5jpdIsMqcPm6VqwTDa2mo6HNvmiqAWmrtAy90gigQaMq8ssBUKxNp1bi
Z2erK7Xvsaqt5OUNniajMnWHs9KYDaSQxflSYcdtCA2hAAAAgBWmCFy7Cau3IKv2Cf3uSY
LxQd5DizOiY4AgaiJQvLt0mPyLW7C/AAVdUPboWIgUtIXz1b8qim59gx+SNvEBjtvImY+A
uv4jfoMOHu3WJmoy2l3zKbYjxQ0c5aYgWQb0Gpdkb8gJWT4bwZjMgRAsGS+WJwrn7YzyLb
YpeV1KBhtEAAAAgQDtFa7vCuUG7iPySparU/0STQ6rxb5e67C1x0JsYfhjqHdQh+m+wRYR
Dl5N5N987r0uc/P13ZjlYAwDLVCKbiR4PCkfBPPzePQuOqqNDb7cTu5pbCXB7nTu4sCJ82
ppwRErkx+uirIsNA9/W94EmXscyjMMnfTzW3sdVWHey+EsCQAAAIEA4i1kf6c6CIfzUbn7
p+NwRLtMRQgRyjs7+pNldCT6RwiVpXWWjuXRsJBMAn19zsM28Xj0QoGbwTqsRSDaY1loGn
QfjXXoRlF7fv9DzdmfF8+LYiLER2x1rX1X6ODHCnNkojvuoXXFueFra4FTZ+5HsPSk2Z6M
lKTxtzHdAHiL8q8AAAARbWlrYWVsQG1pa2FlbC1kZXYBAg==
-----END OPENSSH PRIVATE KEY-----
)**"},
{key_type::ecdsa_sha2_nistp256, ecdsa_fprint,
R"**(-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSBJKGeexNgOgefrZIqvTV8MNwnHMrP
FyzUcuXvLc0QcicHU4MgQOZgIMj94HOthVEldW3Hx6NcX+Xd6BvVfEywAAAAsDOsX7kzrF
+5AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIEkoZ57E2A6B5+t
kiq9NXww3Cccys8XLNRy5e8tzRByJwdTgyBA5mAgyP3gc62FUSV1bcfHo1xf5d3oG9V8TL
AAAAAhAOnXZPTC1E5He4mnpR5yYZiOjtgNcXgM+rBwMmzRV/WSAAAAEW1pa2FlbEBtaWth
ZWwtZGV2AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
)**"}
	};

std::size_t const openssh_test_key_count = sizeof(openssh_test_keys)/sizeof(*openssh_test_keys);

TEST_CASE("load openssh private key", "[unit][crypto]") {
	auto i = GENERATE(range(0ul, openssh_test_key_count));
	CAPTURE(i);

	crypto_test_context ctx;

	auto priv = load_ssh_private_key(to_span(openssh_test_keys[i].privkey), ctx, ctx.call);
	REQUIRE(priv.valid());

	CHECK(priv.type() == openssh_test_keys[i].type);

	byte_vector msg(69, std::byte{'A'});
	auto sig = priv.sign(msg);
	REQUIRE(!sig.empty());

	{
		auto pub = priv.public_key();
		REQUIRE(pub.valid());
		CHECK(pub.fingerprint(ctx, ctx.call) == openssh_test_keys[i].fprint);
		CHECK(pub.verify(msg, sig));
	}

	// serialise
	std::string ser = save_openssh_private_key(priv, ctx, ctx.call);
	auto same_priv = load_ssh_private_key(to_span(ser), ctx, ctx.call);
	REQUIRE(same_priv.valid());
	CHECK(to_byte_vector(priv) == to_byte_vector(same_priv));

}

key_exchange_type const exchanges[] =
	{ key_exchange_type::X25519
	, key_exchange_type::diffie_hellman_group14_sha256
	, key_exchange_type::diffie_hellman_group16_sha512 };

std::size_t const exchange_count = sizeof(exchanges) / sizeof(*exchanges);

TEST_CASE("key exchange", "[unit][crypto]") {
	auto i = GENERATE(range(0ul, exchange_count));
	CAPTURE(i);

	crypto_test_context ctx;

	auto exc1 = ctx.construct_key_exchange(key_exchange_data_type{exchanges[i]}, ctx.call);
	auto exc2 = ctx.construct_key_exchange(key_exchange_data_type{exchanges[i]}, ctx.call);

	REQUIRE(exc1);
	REQUIRE(exc2);

	auto secret1 = exc2->agree(exc1->public_key());
	auto secret2 = exc1->agree(exc2->public_key());

	CHECK(!secret1.empty());
	CHECK(secret1 == secret2);
}

TEST_CASE("ed25519 generate key", "[unit][crypto]") {
	crypto_test_context ctx;

	auto priv = ctx.generate_private_key(private_key_info{key_type::ssh_ed25519}, ctx.call);
	REQUIRE(priv);

	byte_vector msg(69, std::byte{'A'});
	auto sig = priv->sign(msg);
	REQUIRE(!sig.empty());

	auto pub = priv->public_key();
	REQUIRE(pub);

	CHECK(pub->verify(msg, sig));
}

TEST_CASE("ecdsa generate key", "[unit][crypto]") {
	crypto_test_context ctx;

	auto priv = ctx.generate_private_key(private_key_info{key_type::ecdsa_sha2_nistp256}, ctx.call);
	REQUIRE(priv);

	byte_vector msg(69, std::byte{'A'});
	auto sig = priv->sign(msg);
	REQUIRE(!sig.empty());

	auto pub = priv->public_key();
	REQUIRE(pub);

	CHECK(pub->verify(msg, sig));
}

TEST_CASE("rsa generate key", "[unit][crypto]") {
	crypto_test_context ctx;

	auto priv = ctx.generate_private_key(private_key_info{key_type::ssh_rsa, 2048}, ctx.call);
	REQUIRE(priv);

	byte_vector msg(69, std::byte{'A'});
	auto sig = priv->sign(msg);
	REQUIRE(!sig.empty());

	auto pub = priv->public_key();
	REQUIRE(pub);

	CHECK(pub->verify(msg, sig));
}

}