
#include "server.hpp"

namespace securepath::ssh {

ssh_test_server::ssh_test_server(ssh_config const& config, logger& log, out_buffer& buf, crypto_context& context)
: ssh_server(config, log, buf, context)
{
}

std::unique_ptr<ssh_service> ssh_test_server::construct_service(std::string_view name) {
	return nullptr;
}

}