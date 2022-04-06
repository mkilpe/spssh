
#include "crypto.hpp"
#include "random.hpp"
#include "test_buffers.hpp"

#include "ssh/core/kex.hpp"

namespace securepath::ssh::test {
namespace {
struct test_context {
	test_context(logger& l, std::string tag, ssh_config c = {})
	: log(l, tag)
	, config(std::move(c))
	{
		bp.set_random(test_rand);

		//fill init_data
	}

	session_logger log;
	ssh_config config;
	ssh_binary_packet bp{config, log};
	string_io_buffer out_buf;
	crypto_test_context ctx;
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

TEST_CASE("curve25519 sha256 kex", "[unit][crypto]") {
	test_context c_context(test_log(), "[client]", test_client_config());
	test_context s_context(test_log(), "[server]", test_server_config());

	auto c_kex = construct_kex(transport_side::client, kex_type::curve25519_sha256, c_context.kex_c);
	auto s_kex = construct_kex(transport_side::server, kex_type::curve25519_sha256, s_context.kex_c);

	CHECK(false);
}

}