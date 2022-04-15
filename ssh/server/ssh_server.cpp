#include "ssh_server.hpp"

namespace securepath::ssh {

ssh_server::ssh_server(ssh_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: ssh_transport(conf, log, out, std::move(cc))
{
}

handler_result ssh_server::handle_service_request(const_span payload) {
	return {};
}

handler_result ssh_server::handle_transport_packet(ssh_packet_type type, const_span payload) {
	if(type == ssh_service_request) {
		return handle_service_request(payload);
	}
	return handler_result::unknown;
}


}
