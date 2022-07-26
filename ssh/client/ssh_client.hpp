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

	bool user_authenticated() const { return user_authenticated_; }

protected:
	virtual std::unique_ptr<auth_service> construct_auth();
	virtual std::unique_ptr<ssh_service> construct_service(auth_info const&);

protected:
	void on_state_change(ssh_state old_s, ssh_state new_s) override;

	handler_result handle_kex_done(kex const&) override;
	handler_result handle_transport_packet(ssh_packet_type, const_span payload) override;

protected:
	handler_result handle_service_accept(const_span payload);
	handler_result process_service(ssh_packet_type type, const_span payload);
	bool flush() override;
	void start_user_auth();
	void start_service(auth_info const& info);

protected:
	client_config const& config_;
	bool requesting_auth_{};
	bool user_authenticated_{};

	// the current active service (e.g. authentication, user defined service, etc)
	std::unique_ptr<ssh_service> service_;
};

}

#endif
