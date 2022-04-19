#ifndef SP_SHH_CLIENT_AUTH_SERVICE_HEADER
#define SP_SHH_CLIENT_AUTH_SERVICE_HEADER

#include "client_config.hpp"
#include "ssh/core/service/ssh_service.hpp"
#include "ssh/core/auth/auth.hpp"

#include <functional>
#include <list>

namespace securepath::ssh {

struct auth_try {
	auth_type type;
	std::string username;
	std::string service;
};

class logger;
class ssh_transport;
class ssh_private_key;

class client_auth_service : public ssh_service {
public:

	client_auth_service(ssh_transport& transport);

	std::string_view name() const override;
	service_state state() const override;
	handler_result process(ssh_packet_type, const_span payload) override;

public:
	/// use no authentication
	void no_authentication(std::string username, std::string service);

	/// authenticate with password
	void authenticate(std::string username, std::string service, std::string_view password);

	/// authenticate with using private key
	void authenticate(std::string username, std::string service, ssh_private_key const&);

protected:
	virtual void on_banner(std::string_view) = 0;
	// called if single auth try fails, one can try some other authentication combination after this
	virtual void on_auth_fail(auth_try, std::vector<std::string_view> const& methods) = 0;
	// called when single auth try succeeds but more is required to authenticate the user
	virtual void on_auth_success(auth_try, std::vector<std::string_view> const& methods) = 0;
	// called when the user was authenticated
	virtual void on_success(std::string_view username, std::string_view service) = 0;

private:
	void handle_banner(const_span payload);
	void handle_success();
	void handle_failure(const_span payload);

protected:
	ssh_transport& transport_;
	logger& log_;
	service_state state_{service_state::inprogress};
	std::list<auth_try> auths_;
};

/// Simple implementation to use pre-set password and private keys in the config to authenticate user
class default_client_auth : public client_auth_service {
public:
	default_client_auth(ssh_transport& transport, client_config const&);

protected:
	virtual void on_banner(std::string_view) override;
	virtual void on_auth_fail(auth_try, std::vector<std::string_view> const& methods) override;
	virtual void on_auth_success(auth_try, std::vector<std::string_view> const& methods) override;
	virtual void on_success(std::string_view username, std::string_view service) override;

private:
	void populate(std::vector<std::string_view> const& methods);
	void next();

private:
	client_config const& config_;
	std::list<std::function<void()>> auths_;
};

}

#endif
