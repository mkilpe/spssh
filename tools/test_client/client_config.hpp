#ifndef SP_SSH_TOOLS_TEST_CLIENT_CLIENT_CONFIG_HEADER
#define SP_SSH_TOOLS_TEST_CLIENT_CLIENT_CONFIG_HEADER

#include "ssh/client/client_config.hpp"

namespace securepath::ssh {

struct test_client_config : client_config {
	std::string channel = "session";
	std::string subsystem = "sftp";
	/// file of trusted host keys; empty disables host key verification
	std::string known_hosts;
	/// label of the host used in the known hosts file, set from the host and port
	std::string host_label;
};

}

#endif