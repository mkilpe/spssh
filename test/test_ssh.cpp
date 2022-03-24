
#include "log.hpp"
#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/server/ssh_server.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::ssh::test {

struct test_context {
	test_context(logger& l, std::string tag, ssh_config c = {}) : log(l, tag), config(std::move(c)) {}

	session_logger log;
	ssh_config config;
	string_io_buffer out_buf;
};

struct test_client : test_context, ssh_client {
	test_client(logger& l, ssh_config c = {}) : test_context(l, "[client] "), ssh_client(c, log, out_buf) {}
};

struct test_server : test_context, ssh_server {
	test_server(logger& l, ssh_config c = {}) : test_context(l, "[server] "), ssh_server(c, log, out_buf) {}
};

bool run(test_client& client, test_server& server) {
	bool run = true;
	while(run) {
		run = client.process(server.out_buf) != transport_op::disconnected;
		run = server.process(client.out_buf) != transport_op::disconnected || run;
		run = run && (!client.out_buf.empty() || !server.out_buf.empty());
	}
	return client.error() == 0 && server.error() == 0;
}

TEST_CASE("ssh test 1", "[unit]") {
	test_server server(test_log());
	test_client client(test_log());

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::kex);
	CHECK(server.state() == ssh_state::kex);
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