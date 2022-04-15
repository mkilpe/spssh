
#include "auth_service.hpp"
#include "ssh/core/protocol.hpp"
#include "ssh/core/auth/auth.hpp"

namespace securepath::ssh {

std::string_view client_auth_service::name() const {
	return ser::user_auth_service_name;
}

service_state client_auth_service::state() const {
	return state_;
}

handler_result client_auth_service::process(ssh_packet_type, const_span payload) {
	return handler_result::unknown;
}

}