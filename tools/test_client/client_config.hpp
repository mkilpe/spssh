#ifndef SP_SSH_TOOLS_TEST_CLIENT_CLIENT_CONFIG_HEADER
#define SP_SSH_TOOLS_TEST_CLIENT_CLIENT_CONFIG_HEADER

#include "ssh/client/client_config.hpp"

namespace securepath::ssh {

struct test_client_config : client_config {
	std::string subsystem = "sftp";
};

}

#endif