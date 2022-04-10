
#include "crypto.hpp"
#include "random.hpp"
#include "test_buffers.hpp"

#include "ssh/core/kex.hpp"
#include "ssh/core/kex/ecdh.hpp"
#include "ssh/core/packet_ser_impl.hpp"

namespace securepath::ssh::test {
namespace {
struct test_context {
	test_context(logger& l, std::string tag, ssh_config c = {})
	: log(l, tag)
	, config(std::move(c))
	{
		bp.set_random(test_rand);

		//fill init_data
		init_data.local_ver = ssh_version{"2.0", "unit-test"};
		init_data.remote_ver = ssh_version{"2.0", "unit-test"};
		init_data.local_kexinit = byte_vector(64, std::byte{'A'});
		init_data.remote_kexinit = byte_vector(64, std::byte{'A'});
	}

	span data(test_context& in) {
		static std::byte buf[512];
		if(bp.try_decode_header(in.out_buf.get())) {
			return bp.decrypt_packet(in.out_buf.get(), buf);
		}
		return {};
	}

	session_logger log;
	ssh_config config;
	ssh_binary_packet bp{config, log};
	string_io_buffer out_buf;
	crypto_test_context ctx{log};
	kex_init_data init_data;
	kex_context kex_c{bp, out_buf, init_data, ctx, ctx.call};
};
}


static ssh_config test_client_config() {
	ssh_config c;
	c.side = transport_side::client;
	c.algorithms.host_keys = {key_type::ssh_ed25519};
	c.algorithms.kexes = {kex_type::curve25519_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm};
	return c;
}

static ssh_config test_server_config() {
	ssh_config c;
	c.side = transport_side::server;
	c.algorithms.host_keys = {key_type::ssh_ed25519};
	c.algorithms.kexes = {kex_type::curve25519_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm};

	crypto_test_context crypto;

	std::vector<ssh_private_key> keys;
	keys.push_back(crypto.test_ed25519_private_key());
	c.set_host_keys_for_server(std::move(keys));

	return c;
}

crypto_configuration const test_conf = {
	kex_type::curve25519_sha256, key_type::ssh_ed25519,
	{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none},
	{cipher_type::aes_256_gcm, mac_type::aes_256_gcm, compress_type::none}};

struct client_server_kex {
	client_server_kex() {
		c_kex = construct_kex(transport_side::client, kex_type::curve25519_sha256, c_context.kex_c);
		s_kex = construct_kex(transport_side::server, kex_type::curve25519_sha256, s_context.kex_c);

		REQUIRE(c_kex);
		REQUIRE(s_kex);

		c_kex->set_crypto_configuration(test_conf);
		s_kex->set_crypto_configuration(test_conf);

		CHECK(c_kex->state() == kex_state::none);

		CHECK(c_kex->initiate() == kex_state::inprogress);
		CHECK(s_kex->initiate() == kex_state::inprogress);
		CHECK(c_kex->state() == kex_state::inprogress);
		CHECK(s_kex->state() == kex_state::inprogress);
	}

	test_context c_context{test_log(), "[client] ", test_client_config()};
	test_context s_context{test_log(), "[server] ", test_server_config()};
	std::unique_ptr<kex> c_kex;
	std::unique_ptr<kex> s_kex;
};

TEST_CASE("curve25519 sha256 kex", "[unit][crypto][kex]") {
	client_server_kex k;

	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), k.s_context.data(k.c_context)) == kex_state::succeeded);
	CHECK(k.c_kex->handle(ssh_packet_type(ssh_kex_ecdh_reply), k.c_context.data(k.s_context)) == kex_state::succeeded);
	CHECK(k.c_kex->state() == kex_state::succeeded);
	CHECK(k.s_kex->state() == kex_state::succeeded);
	CHECK(k.c_kex->error() == ssh_noerror);
	CHECK(k.s_kex->error() == ssh_noerror);
}

TEST_CASE("curve25519 sha256 kex different version", "[unit][crypto][kex]") {
	client_server_kex k;

	// change the client local ssh version
	k.c_context.init_data.local_ver.ssh = "1.0";

	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), k.s_context.data(k.c_context)) == kex_state::succeeded);
	CHECK(k.c_kex->handle(ssh_packet_type(ssh_kex_ecdh_reply), k.c_context.data(k.s_context)) == kex_state::error);
	CHECK(k.c_kex->state() == kex_state::error);
	CHECK(k.s_kex->state() == kex_state::succeeded);
	CHECK(k.c_kex->error() == ssh_key_exchange_failed);
	CHECK(k.s_kex->error() == ssh_noerror);
}

TEST_CASE("curve25519 sha256 kex bad client packet 1", "[unit][crypto][kex]") {
	client_server_kex k;
	byte_vector buf;
	// X25519 public key is 32 bytes, so this one is too short
	std::vector too_short(31, std::byte{'A'});
	REQUIRE(ser::serialise_to_vector<ser::kex_ecdh_init>(buf, to_string_view(too_short)));
	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), buf) == kex_state::error);
	CHECK(k.s_kex->state() == kex_state::error);
}

TEST_CASE("curve25519 sha256 kex bad client packet 2", "[unit][crypto][kex]") {
	client_server_kex k;
	byte_vector buf;
	// right size but all zeroes
	std::vector bad(32, std::byte{0});
	REQUIRE(ser::serialise_to_vector<ser::kex_ecdh_init>(buf, to_string_view(bad)));
	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), buf) == kex_state::error);
	CHECK(k.s_kex->state() == kex_state::error);
}

TEST_CASE("curve25519 sha256 kex bad server packet 1", "[unit][crypto][kex]") {
	client_server_kex k;

	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), k.s_context.data(k.c_context)) == kex_state::succeeded);

	ser::kex_ecdh_reply::load packet(ser::match_type_t, k.c_context.data(k.s_context));
	REQUIRE(packet);
	auto & [host_key, server_eph_key, sig] = packet;

	byte_vector buf;
	// right size but all zeroes
	std::vector bad(32, std::byte{0});
	REQUIRE(ser::serialise_to_vector<ser::kex_ecdh_reply>(buf, host_key, to_string_view(bad), sig));

	CHECK(k.c_kex->handle(ssh_packet_type(ssh_kex_ecdh_reply), buf) == kex_state::error);
	CHECK(k.c_kex->state() == kex_state::error);
}

TEST_CASE("curve25519 sha256 kex bad server packet 2", "[unit][crypto][kex]") {
	client_server_kex k;

	CHECK(k.s_kex->handle(ssh_packet_type(ssh_kex_ecdh_init), k.s_context.data(k.c_context)) == kex_state::succeeded);

	ser::kex_ecdh_reply::load packet(ser::match_type_t, k.c_context.data(k.s_context));
	REQUIRE(packet);
	auto & [host_key, server_eph_key, sig] = packet;

	byte_vector buf;
	std::string bad_host_key(host_key);
	//flip a bit
	bad_host_key[bad_host_key.size()/2] ^= 0x01;

	REQUIRE(ser::serialise_to_vector<ser::kex_ecdh_reply>(buf, bad_host_key, server_eph_key, sig));

	CHECK(k.c_kex->handle(ssh_packet_type(ssh_kex_ecdh_reply), buf) == kex_state::error);
	CHECK(k.c_kex->state() == kex_state::error);
}

}