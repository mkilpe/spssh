#ifndef SP_SHH_SERVICE_HANDLER_HEADER
#define SP_SHH_SERVICE_HANDLER_HEADER

#include "ssh_transport.hpp"
#include "service/ssh_service.hpp"

namespace securepath::ssh {


/** \brief Common base class for client and server to handle services
 */
class service_handler : public ssh_transport {
public:
	service_handler(ssh_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

	bool user_authenticated() const { return user_authenticated_; }
protected:
	virtual std::unique_ptr<auth_service> construct_auth() = 0;
	virtual std::unique_ptr<ssh_service> construct_service(auth_info const&);

protected:
	void init_service();
	void start_user_auth();
	void start_service(auth_info const& info);
	bool flush() override;

protected:
	bool requesting_auth_{};
	bool user_authenticated_{};
	std::unique_ptr<ssh_service> service_;
};

}

#endif
