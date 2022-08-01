#ifndef SP_SHH_SERVER_HEADER
#define SP_SHH_SERVER_HEADER

#include "ssh/core/service_handler.hpp"

namespace securepath::ssh {


/** \brief SSH Version 2 Server side
 */
class ssh_server : public service_handler {
public:
	ssh_server(ssh_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

protected:
	handler_result handle_transport_packet(ssh_packet_type, const_span payload) override;
	void handle_service_request(const_span payload);
	handler_result process_service(ssh_packet_type type, const_span payload);
};

}

#endif
