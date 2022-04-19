#ifndef SP_SHH_CLIENT_HEADER
#define SP_SHH_CLIENT_HEADER

#include "auth_service.hpp"
#include "client_config.hpp"
#include "ssh/core/ssh_transport.hpp"

namespace securepath::ssh {


/** \brief SSH Version 2 Client side
 */
class ssh_client : public ssh_transport {
public:
	ssh_client(client_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

	void start_auth(std::string service);

protected:
	virtual std::unique_ptr<ssh_service> construct_service(std::string_view name);

protected:
	void on_state_change(ssh_state old_s, ssh_state new_s) override;

	handler_result handle_kex_done(kex const&) override;
	handler_result handle_transport_packet(ssh_packet_type, const_span payload) override;

protected:
	handler_result handle_service_accept(const_span payload);
	handler_result handle_user_auth(ssh_packet_type, const_span payload);
	handler_result handle_service_packet(ssh_packet_type, const_span payload);
	void start_user_auth();

protected:
	client_config const& config_;
	bool requesting_auth_{};
	// this is the current active service (e.g. user authentication, connection or user provided)
	std::unique_ptr<ssh_service> service_;
};

}

#endif
