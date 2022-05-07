
#include "server.hpp"
#include "auth_service.hpp"

namespace securepath::ssh {

ssh_test_server::ssh_test_server(server_config const& config, logger& log, out_buffer& buf, crypto_context& context)
: ssh_server(config, log, buf, context)
, config_(config)
{
}

std::unique_ptr<ssh_service> ssh_test_server::construct_service(std::string_view name) {
	if(name == user_auth_service_name) {
		auto serv = std::make_unique<server_test_auth_service>(*this, config_.auth);
		serv->add_password("test", "some");
		serv->add_pk("test", "SHA256:AJxI+SMrILxnTIinoWVeFhz3BGq9zH+VyOcH6IsJV/0");
		return serv;
	}
	return nullptr;
}

}