#ifndef SP_SHH_SERVER_HEADER
#define SP_SHH_SERVER_HEADER

#include "ssh/core/ssh_transport.hpp"
#include "ssh/core/service/ssh_service.hpp"

namespace securepath::ssh {


/** \brief SSH Version 2 Server side
 */
class ssh_server : public ssh_transport {
public:
	ssh_server(ssh_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

protected:
	virtual std::unique_ptr<auth_service> construct_auth() = 0;
	virtual std::unique_ptr<ssh_service> construct_service(auth_info const&);
	handler_result handle_transport_packet(ssh_packet_type, const_span payload) override;

protected:
	void start_user_auth();
	void start_service(auth_info const& info);
	void handle_service_request(const_span payload);
	handler_result process_service(ssh_packet_type type, const_span payload);

protected:
	std::unique_ptr<ssh_service> service_;
};

}

#endif
