
#ifndef SP_SSH_TEST_UTIL_HEADER
#define SP_SSH_TEST_UTIL_HEADER

#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/core/service/ssh_service.hpp"
#include "ssh/core/ssh_transport.hpp"

namespace securepath::ssh::test {

struct test_context {
	test_context(logger& l, std::string tag)
	: slog(l, tag)
	{
	}

	mutable session_logger slog;
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

template<typename Client, typename Server>
bool run(Client& client, Server& server) {
	bool run = true;
	while(run) {
		auto client_op = client.process(server.out_buf);
		// if the client is waiting user action, break out of the running loop so it can be handled
		run = client_op != transport_op::disconnected && client_op != transport_op::pending_action;

		auto server_op = server.process(client.out_buf);
		run = run && server_op != transport_op::disconnected && server_op != transport_op::pending_action;
		if(server_op == transport_op::disconnected) {
			// give the client change to process once more
			while(client.process(server.out_buf) != transport_op::disconnected && !server.out_buf.empty()) {}
		}
		run = run && (!client.out_buf.empty() || !server.out_buf.empty());
	}
	return client.error() == 0 && server.error() == 0;
}

}

#endif
