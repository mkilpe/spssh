#ifndef SP_SHH_CLIENT_AUTH_SERVICE_HEADER
#define SP_SHH_CLIENT_AUTH_SERVICE_HEADER

#include "client_config.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/core/service/ssh_service.hpp"
#include "ssh/core/auth/auth.hpp"

#include <functional>
#include <list>

namespace securepath::ssh {

struct auth_try {
	auth_type type{};
	std::string username;
	std::string service;
	// this is set if we are doing first public key check query, so that we can do the actual auth if succeeding
	ssh_private_key private_key;
};


enum class interactive_result {
	cancelled,
	pending,
	data
};

class transport_base;
class ssh_private_key;

class client_auth_service : public auth_service {
public:

	client_auth_service(transport_base& transport);

	std::string_view name() const override;
	service_state state() const override;
	bool init() override;
	handler_result process(ssh_packet_type, const_span payload) override;
	auth_info info_authenticated() const override;

public:
	/// use no authentication (or query supported auth methods if auth required)
	void no_authentication(std::string username, std::string service);

	/// authenticate with password
	void authenticate(std::string username, std::string service, std::string_view password);

	/// authenticate with using private key
	void authenticate(std::string username, std::string service, ssh_private_key const&);

	/// do pk key check query to see if using the key would be accepted
	void authenticate_with_key_check(std::string username, std::string service, ssh_private_key pk);

	/// authenticate with host, takes host private key, fully qualified domain name and user name on the client host
	void authenticate_host(std::string username, std::string service, ssh_private_key const&, std::string_view fqdn, std::string_view host_user);

	/// authenticate with interactive
	void authenticate_interactive(std::string username, std::string service, std::vector<std::string_view> const& submethods);

protected:
	virtual void on_banner(std::string_view) = 0;
	// called if single auth try fails, one can try some other authentication combination after this
	virtual void on_auth_fail(auth_try, std::vector<std::string_view> const& methods) = 0;
	// called when single auth try succeeds but more is required to authenticate the user
	virtual void on_auth_success(auth_try, std::vector<std::string_view> const& methods) = 0;
	// called when the user was authenticated
	virtual void on_success(std::string_view username, std::string_view service) = 0;
	// called for interactive authentication request
	virtual interactive_result on_interactive(interactive_request const&, std::vector<std::string>& results) = 0;
private:
	void handle_banner(const_span payload);
	void handle_success();
	void handle_failure(const_span payload);
	void handle_pk_auth_ok(const_span payload);
	void handle_change_password(const_span payload);
	handler_result handle_interactive_request(const_span payload);
	void send_interactive_response(std::vector<std::string> const& results);

protected:
	transport_base& transport_;
	logger& log_;
	service_state state_{service_state::inprogress};
	std::list<auth_try> auths_;
	std::optional<auth_try> authenticated_;
};

/*
	Simple implementation to use pre-set password and private keys in the config to authenticate user
	Does not support interactive authentication (always returns cancelled), one has to override the on_interactive to support that.
*/
class default_client_auth : public client_auth_service {
public:
	default_client_auth(transport_base& transport, client_config const&);

protected:
	void on_banner(std::string_view) override;
	void on_auth_fail(auth_try, std::vector<std::string_view> const& methods) override;
	void on_auth_success(auth_try, std::vector<std::string_view> const& methods) override;
	void on_success(std::string_view username, std::string_view service) override;
	interactive_result on_interactive(interactive_request const&, std::vector<std::string>& results) override;

private:
	void populate(std::vector<std::string_view> const& methods);
	void next();

private:
	client_config const& config_;
	std::list<std::function<void()>> auths_;
};

}

#endif
