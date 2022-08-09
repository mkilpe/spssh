
#include "config.hpp"
#include "configs.hpp"
#include "util.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/server/ssh_server.hpp"
#include "test/util/server_auth_service.hpp"

#if defined(USE_NETTLE) && defined(USE_CRYPTOPP)
#	include "ssh/crypto/nettle/crypto_context.hpp"
#	include "ssh/crypto/cryptopp/crypto_context.hpp"
#endif

namespace securepath::ssh::test {
namespace {

struct test_client : test_context, client_config, ssh_client {
	test_client(logger& l, client_config c = {}, crypto_context ccontext = default_crypto_context())
	: test_context(l, "[client] ")
	, client_config{std::move(c)}
	, ssh_client(*this, slog, out_buf, std::move(ccontext))
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
	test_server(logger& l, ssh_config c = {}, crypto_context ccontext = default_crypto_context())
	: test_context(l, "[server] ")
	, server_config{std::move(c)}
	, ssh_server(*this, slog, out_buf, std::move(ccontext))
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

TEST_CASE("ssh test", "[unit]") {
	test_server server(test_log(), test_server_config());
	test_client client(test_log(), test_client_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
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

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());
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

TEST_CASE("ssh test 2", "[unit]") {
	test_server server(test_log(), test_server_aes_ctr_config());
	test_client client(test_log(), test_client_aes_ctr_config());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
}

#if defined(USE_NETTLE) && defined(USE_CRYPTOPP)
TEST_CASE("ssh crypto interoperability 1", "[unit]") {
	test_server server(test_log(), test_server_config(), nettle::create_nettle_context());
	test_client client(test_log(), test_client_config(), cryptopp::create_cryptopp_context());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
}

TEST_CASE("ssh crypto interoperability 2", "[unit]") {
	test_server server(test_log(), test_server_config(), cryptopp::create_cryptopp_context());
	test_client client(test_log(), test_client_config(), nettle::create_nettle_context());

	server.set_test_auth();
	client.set_test_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);
	CHECK(client.user_authenticated());
	CHECK(server.user_authenticated());

	client.send_ignore(10);
	server.send_ignore(25);
	CHECK(run(client, server));
}
#endif

}