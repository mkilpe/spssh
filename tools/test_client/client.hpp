#ifndef SP_SSH_TOOLS_TEST_CLIENT_CLIENT_HEADER
#define SP_SSH_TOOLS_TEST_CLIENT_CLIENT_HEADER

#include "client_config.hpp"
#include "tools/common/config_parser.hpp"
#include "tools/common/event_loop.hpp"
#include "ssh/client/client_config.hpp"

namespace securepath::ssh {

struct test_client_commands : test_client_config, securepath::command_parser {
	bool help{};
	std::string host;
	std::uint16_t port{22};
	std::string config_file;

	config_parser config;

	test_client_commands();
	void create_config(logger& log);
};

class test_client {
public:
	test_client(test_client_commands const&);
	~test_client();

	int run();

private:
	securepath::stdout_logger log_;
	single_thread_event_loop main_loop_;

	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif