
#include "crypto.hpp"
#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/server/ssh_server.hpp"

namespace securepath::ssh::test {
namespace {
struct test_context {
	test_context(logger& l, std::string tag, ssh_config c = {}, bool is_client = true)
	: log(l, tag), config(std::move(c))
	{
		// make sure we have correct side set
		if(is_client) {
			config.side = transport_side::client;
		} else {
			config.side = transport_side::server;
		}
	}

	session_logger log;
	ssh_config config;
	string_io_buffer out_buf;
};

struct test_client : test_context, ssh_client {
	test_client(logger& l, ssh_config c = {})
	: test_context(l, "[client] ", std::move(c), true), ssh_client(test_context::config, log, out_buf)
	{
	}
};

struct test_server : test_context, ssh_server {
	test_server(logger& l, ssh_config c = {})
	: test_context(l, "[server] ", std::move(c), false), ssh_server(test_context::config, log, out_buf)
	{
	}
};
}

bool run(test_client& client, test_server& server) {
	bool run = true;
	while(run) {
		run = client.process(server.out_buf) != transport_op::disconnected;
		if(server.process(client.out_buf) == transport_op::disconnected) {
			run = false;
			// give the client change to process once more
			client.process(server.out_buf);
		}
		run = run && (!client.out_buf.empty() || !server.out_buf.empty());
	}
	return client.error() == 0 && server.error() == 0;
}

static ssh_config test_client_config() {
	ssh_config c;
	c.algorithms.host_keys = {key_type::ssh_ed25519};
	c.algorithms.kexes = {kex_type::curve25519_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm};

	//c.random_packet_padding = false;

	return c;
}

static ssh_config test_server_config() {
	ssh_config c;
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


TEST_CASE("ssh test", "[unit]") {
	test_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
}

TEST_CASE("ssh test guess", "[unit]") {
	ssh_config s = test_server_config();
	s.guess_kex_packet = true;
	ssh_config c = test_client_config();
	c.guess_kex_packet = true;
	test_server server(test_log(), std::move(s));
	test_client client(test_log(), std::move(c));

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
}

TEST_CASE("ssh failing version exchange", "[unit]") {
	test_server server(test_log());
	test_client client(test_log(), ssh_config{.my_version = ssh_version{.ssh="1.0"}});

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);
	// the ssh_transport tries to send kexinit before reading the disconnect packet
	CHECK(client.error() != ssh_error_code::ssh_noerror);
	CHECK(server.error() == ssh_error_code::ssh_protocol_version_not_supported);
}

}