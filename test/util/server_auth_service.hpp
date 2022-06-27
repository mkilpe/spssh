#ifndef SP_SSH_TEST_UTIL_SERVER_AUTH_SERVICE_HEADER
#define SP_SSH_TEST_UTIL_SERVER_AUTH_SERVICE_HEADER

#include "ssh/server/auth_service.hpp"

namespace securepath::ssh {

struct test_host_data {
	std::string fingerprint;
	std::string domain;
	std::string host_user;
};

struct test_interactive_data {
	std::vector<interactive_request> requests;
	std::vector<std::vector<std::string>> responses;
};

struct test_auth_data {
	void add_password(std::string const& user, std::string password);
	void add_pk(std::string const& user, std::string fp);
	void add_host(std::string const& user, std::string fp, std::string domain, std::string host_user);
	void add_interactive(std::string const& user, std::vector<interactive_request> req, std::vector<std::vector<std::string>> res);

	std::map<std::string, std::string, std::less<>> passwords;
	std::map<std::string, std::string, std::less<>> pk_fingerprints;
	std::map<std::string, test_host_data, std::less<>> hosts;
	std::map<std::string, test_interactive_data, std::less<>> interactives;
};

// simple container for passwords/fingerprints to test, _only to test_
class server_test_auth_service : public server_auth_service {
public:
	server_test_auth_service(transport_base& transport, auth_config const&, test_auth_data data);

protected:
	auth_state verify_password(auth_context const&, std::string_view password) override;
	auth_state verify_public_key(auth_context const&, ssh_public_key const&) override;
	auth_state verify_host(auth_context const&, ssh_public_key const&, std::string_view fqdn, std::string_view host_user) override;
	auth_state start_interactive(auth_context const&, std::vector<std::string_view> const& submethods, interactive_request& request) override;
	auth_interactive_state verify_interactive(auth_context const&, std::vector<std::string_view> const& responses) override;

	void auth_succeeded(auth_context const&) override;

private:
	transport_base& transport_;
	test_auth_data data_;
	std::size_t interactive_state{};
};

}

#endif