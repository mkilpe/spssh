
#include "auth_service.hpp"

namespace securepath::ssh {

server_test_auth_service::server_test_auth_service(ssh_transport& transport, auth_config const& config)
: server_auth_service(transport, config)
, transport_(transport)
{
}

auth_state server_test_auth_service::verify_password(auth_context const& context, std::string_view password) {
	auto it = passwords_.find(context.username);
	return it != passwords_.end() && password == it->second ? auth_state::succeeded : auth_state::failed;
}

auth_state server_test_auth_service::verify_public_key(auth_context const& context, ssh_public_key const& pk) {
	auto it = pk_fingerprints_.find(context.username);
	return it != pk_fingerprints_.end()
		&& pk.fingerprint(transport_.crypto(), transport_.call_context()) == it->second
			? auth_state::succeeded : auth_state::failed;
}

void server_test_auth_service::auth_succeeded(auth_context const& context) {
	transport_.log().log(logger::info, "auth succeeded");
}

void server_test_auth_service::add_password(std::string const& user, std::string password) {
	passwords_[user] = std::move(password);
}

void server_test_auth_service::add_pk(std::string const& user, std::string fp) {
	pk_fingerprints_[user] = std::move(fp);
}

}
