#include "ssh_connection.hpp"
#include "conn_protocol.hpp"

#include "ssh/core/ssh_transport.hpp"
#include "ssh/core/service/names.hpp"

namespace securepath::ssh {

ssh_connection::ssh_connection(ssh_transport& t)
: transport_(t)
{
}

std::string_view ssh_connection::name() const {
	return connection_service_name;
}

service_state ssh_connection::state() const {
	return state_;
}

bool ssh_connection::init() {
	return true;
}

handler_result ssh_connection::process(ssh_packet_type, const_span payload) {
	return handler_result::unknown;
}

}
