
#include "server.hpp"
#include "test/util/server_auth_service.hpp"

namespace securepath::ssh {

ssh_test_server::ssh_test_server(server_config const& config, logger& log, out_buffer& buf, crypto_context& context)
: ssh_server(config, log, buf, context)
, config_(config)
{
}

std::unique_ptr<auth_service> ssh_test_server::construct_auth() {
	test_auth_data data;
	data.add_password("test", "some");
	data.add_pk("test", "SHA256:AJxI+SMrILxnTIinoWVeFhz3BGq9zH+VyOcH6IsJV/0");
	return std::make_unique<server_test_auth_service>(*this, config_.auth, std::move(data));
}

std::unique_ptr<ssh_service> ssh_test_server::construct_service(auth_info const&) {
	return nullptr;
}

}