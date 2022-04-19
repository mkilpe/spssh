#ifndef SP_SHH_CLIENT_CLIENT_CONFIG_HEADER
#define SP_SHH_CLIENT_CLIENT_CONFIG_HEADER

#include "ssh/core/ssh_config.hpp"
#include "ssh/core/service/names.hpp"

namespace securepath::ssh {

struct client_config : ssh_config {
	/// username that is used for authentication
	std::string username;

	/// password for authentication
	std::string password;

	/// service that we authenticate for
	std::string service{connection_service_name};
};

}

#endif
