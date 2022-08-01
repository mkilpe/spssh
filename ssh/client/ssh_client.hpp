#ifndef SP_SHH_CLIENT_HEADER
#define SP_SHH_CLIENT_HEADER

#include "auth_service.hpp"
#include "client_config.hpp"
#include "ssh/core/service_handler.hpp"

namespace securepath::ssh {


/** \brief SSH Version 2 Client side
 */
class ssh_client : public service_handler {
public:
	ssh_client(client_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

	void start_auth(std::string service);

protected:
	void on_state_change(ssh_state old_s, ssh_state new_s) override;

	handler_result handle_kex_done(kex const&) override;
	handler_result handle_transport_packet(ssh_packet_type, const_span payload) override;
	std::unique_ptr<auth_service> construct_auth() override;

	handler_result handle_service_accept(const_span payload);
	handler_result process_service(ssh_packet_type type, const_span payload);

protected:
	client_config const& config_;
};

}

#endif
