#ifndef SP_SSH_TOOLS_TEST_SERVER_AUTH_SERVICE_HEADER
#define SP_SSH_TOOLS_TEST_SERVER_AUTH_SERVICE_HEADER

#include "ssh/server/auth_service.hpp"

namespace securepath::ssh {

// simple container for passwords/fingerprints to test, _only to test_
class server_test_auth_service : public server_auth_service {
public:
	server_test_auth_service(ssh_transport& transport, auth_config const&);

	void add_password(std::string const& user, std::string password);
	void add_pk(std::string const& user, std::string fp);

protected:
	auth_state verify_password(auth_context const&, std::string_view password) override;
	auth_state verify_public_key(auth_context const&, ssh_public_key const&) override;
	void auth_succeeded(auth_context const&) override;

private:
	ssh_transport& transport_;
	std::map<std::string, std::string, std::less<>> passwords_;
	std::map<std::string, std::string, std::less<>> pk_fingerprints_;
};

}

#endif