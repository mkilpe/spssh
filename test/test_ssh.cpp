
#include "crypto.hpp"
#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/server/ssh_server.hpp"
#include "ssh/server/server_config.hpp"
#include "test/util/server_auth_service.hpp"

namespace securepath::ssh::test {
namespace {
struct test_context {
	test_context(logger& l, std::string tag)
	: slog(l, tag)
	{
	}

	session_logger slog;
	string_io_buffer out_buf;
};

struct dummy_service : ssh_service {
	std::string_view name() const override { return "dummy-service"; }
	service_state state() const override { return service_state::inprogress; }
	bool init() override { return true; }
	handler_result process(ssh_packet_type, const_span) override {
		return handler_result::handled;
	}
};

struct test_client : test_context, client_config, ssh_client {
	test_client(logger& l, client_config c = {})
	: test_context(l, "[client] ")
	, client_config{std::move(c)}
	, ssh_client(*this, slog, out_buf)
	{
		side = transport_side::client;
	}

	void set_test_auth() {
		username = "test";
		password = "some";
		service = "dummy-service";
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			return std::make_unique<dummy_service>();
		}
		return nullptr;
	}
};

struct test_server : test_context, server_config, ssh_server {
	test_server(logger& l, ssh_config c = {})
	: test_context(l, "[server] ")
	, server_config{std::move(c)}
	, ssh_server(*this, slog, out_buf)
	{
		side = transport_side::server;
	}

	std::unique_ptr<auth_service> construct_auth() override {
		return std::make_unique<server_test_auth_service>(*this, auth, std::move(auth_data));
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			return std::make_unique<dummy_service>();
		}
		return nullptr;
	}

	void set_test_auth() {
		//void add_pk(std::string const& user, std::string fp)
		//void add_password(std::string const& user, std::string password);
		auth_data.add_password("test", "some");
		auth.service_auth["dummy-service"] = req_auth{};
	}

	test_auth_data auth_data;
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

static client_config test_client_config() {
	client_config c;
	c.algorithms.host_keys = {key_type::ssh_ed25519};
	c.algorithms.kexes = {kex_type::curve25519_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm};

	//c.random_packet_padding = false;

	return c;
}

static server_config test_server_config() {
	server_config c;
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

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::service);
	CHECK(server.state() == ssh_state::service);

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::service);
	CHECK(server.state() == ssh_state::service);
}

TEST_CASE("ssh test guess", "[unit]") {
	server_config s = test_server_config();
	s.guess_kex_packet = true;
	client_config c = test_client_config();
	c.guess_kex_packet = true;
	test_server server(test_log(), std::move(s));
	test_client client(test_log(), std::move(c));

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::service);
	CHECK(server.state() == ssh_state::service);
}

TEST_CASE("ssh failing version exchange", "[unit]") {
	test_server server(test_log());
	client_config c = test_client_config();
	test_client client(test_log(), client_config{ssh_config{.my_version = ssh_version{.ssh="1.0"}}});

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);
	// the ssh_transport tries to send kexinit before reading the disconnect packet
	CHECK(client.error() != ssh_error_code::ssh_noerror);
	CHECK(server.error() == ssh_error_code::ssh_protocol_version_not_supported);
}


TEST_CASE("ssh no kex", "[unit]") {
	test_server server(test_log());
	test_client client(test_log());

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(client.error() == ssh_error_code::ssh_key_exchange_failed);
	CHECK(server.error() == ssh_error_code::ssh_key_exchange_failed);
}

TEST_CASE("ssh failing auth (bad service)", "[unit]") {
	test_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	client.set_test_auth();

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(client.error() == ssh_error_code::ssh_service_not_available);
	CHECK(server.error() == ssh_error_code::ssh_service_not_available);
}


TEST_CASE("ssh failing auth (no method)", "[unit]") {
	test_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	client.set_test_auth();
	server.auth.service_auth["dummy-service"] = req_auth{};
	server.auth.num_of_tries = 1;

	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(client.error() == ssh_error_code::ssh_no_more_auth_methods_available);
	CHECK(server.error() == ssh_error_code::ssh_no_more_auth_methods_available);
}


}