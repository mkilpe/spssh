#ifndef SP_SHH_SERVER_SERVER_CONFIG_HEADER
#define SP_SHH_SERVER_SERVER_CONFIG_HEADER

#include "ssh/core/ssh_config.hpp"
#include "auth_service.hpp"

namespace securepath::ssh {

struct server_config : ssh_config {
	// configuration for user authentication
	auth_config auth;
};

}

#endif
