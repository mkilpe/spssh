#ifndef SP_SHH_SERVER_AUTH_SERVICE_HEADER
#define SP_SHH_SERVER_AUTH_SERVICE_HEADER

#include "ssh/core/auth/auth.hpp"
#include "ssh/core/service/ssh_service.hpp"
#include "ssh/core/service/names.hpp"
#include "ssh/core/ssh_transport.hpp"

#include <map>

namespace securepath::ssh {

enum class auth_state {
	failed,
	pending,
	succeeded
};

enum class auth_interactive_state {
	failed,
	pending,
	more,
	succeeded
};

struct req_auth {
	// bit mask of required authentication methods, (password|publickey) requires that user authenticates with both.
	auth_bits required{};
	// bit mask of allowed authentication methods. if required is 0 then any of the allowed authentication methods are accepted
	auth_bits allowed{auth_type::public_key|auth_type::password};
	/* number of individual authentications required.
	   if allowed is (password|publickey|hostbased) and num_req is 2, then any two of the allowed is required.
	   num_req >= count(required) or the user cannot be authenticated successfully.
	   if required and num_req are both 0, then no authentication is required
	*/
	std::uint16_t num_req{1};
};

struct auth_config {
	std::map<std::string, req_auth, std::less<>> service_auth = {{std::string(connection_service_name), req_auth{}}};
	// how many failed attempts are allowed
	std::size_t num_of_tries{5};
	// banner message
	std::string banner;
};

struct auth_context {
	std::string username;
	std::string service;
	req_auth req;
	auth_bits successful{};

public:
	// returns methods that can still be used (so does not contain already succeeded ones)
	auth_bits viable_methods() const;
	// list of methods that can be used (excluding already successful ones)
	std::vector<std::string_view> viable_method_list() const;
	// list of succeeded methods
	std::vector<std::string_view> succeeded_method_list() const;
};

/*
 * auth methods per service requested
 * require one or more methods for successful authentication
 *
*/
class server_auth_service : public auth_service {
public:
	server_auth_service(ssh_transport& transport, auth_config const&);

	std::string_view name() const override;
	service_state state() const override;
	bool init() override;
	handler_result process(ssh_packet_type, const_span payload) override;
	auth_info info_authenticated() const override;

protected:
	// called to verify password, in case previous call returned pending state, this will be called again on next processing round
	virtual auth_state verify_password(auth_context const&, std::string_view password) = 0;

	// called to verify public key, in case previous call returned pending state, this will be called again on next processing round
	virtual auth_state verify_public_key(auth_context const&, ssh_public_key const&) = 0;

	// called to verify host-based authentication
	virtual auth_state verify_host(auth_context const&, ssh_public_key const&, std::string_view fqdn, std::string_view host_user) = 0;

	// called when interactive method is requested, the returned auth_state reflects if the method is available
	virtual auth_state start_interactive(auth_context const&, std::vector<std::string_view> const& submethods, interactive_request& request) = 0;

	// called when response received to interactive request
	virtual auth_interactive_state verify_interactive(auth_context const&, std::vector<std::string_view> const& responses) = 0;

	// this is called then user authentication succeeded and the service is hence done
	virtual void auth_succeeded(auth_context const&) = 0;

	// send interactive_request; this can be called from verify_interactive if more information is needed from client
	void send_interactive_request(interactive_request const& req);
protected:
	bool update_current(std::string_view user, std::string_view service);
	void handle_none_request();
	void handle_auth_success(auth_type succ);
	void handle_auth_failure(auth_type fail);
	handler_result handle_password_request(const_span payload);
	handler_result handle_pk_query(ssh_public_key const& key, std::string_view pk_blob);
	handler_result handle_pk_auth(ssh_public_key const& key, const_span msg, const_span sig);
	handler_result handle_pk_request(const_span payload);
	handler_result handle_hostbased_request(const_span payload);
	handler_result handle_interactive_request(const_span payload);
	handler_result handle_interactive_response(const_span payload);
	bool verify_user_auth_signature(ssh_public_key const& key, const_span p_msg, const_span sig) const;
private:
	ssh_transport& transport_;
	auth_config const& auth_config_;
	logger& log_;

	service_state state_{service_state::inprogress};

	std::size_t tries_left{};
	auth_context current_;
	bool interactive_in_progress_{};
};

}

#endif
