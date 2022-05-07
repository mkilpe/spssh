
#include "server_auth_service.hpp"

namespace securepath::ssh {


void test_auth_data::add_password(std::string const& user, std::string password) {
	passwords[user] = std::move(password);
}

void test_auth_data::add_pk(std::string const& user, std::string fp) {
	pk_fingerprints[user] = std::move(fp);
}

server_test_auth_service::server_test_auth_service(ssh_transport& transport, auth_config const& config, test_auth_data data)
: server_auth_service(transport, config)
, transport_(transport)
, data_(std::move(data))
{
}

auth_state server_test_auth_service::verify_password(auth_context const& context, std::string_view password) {
	auto it = data_.passwords.find(context.username);
	return it != data_.passwords.end() && password == it->second ? auth_state::succeeded : auth_state::failed;
}

auth_state server_test_auth_service::verify_public_key(auth_context const& context, ssh_public_key const& pk) {
	auto it = data_.pk_fingerprints.find(context.username);
	return it != data_.pk_fingerprints.end()
		&& pk.fingerprint(transport_.crypto(), transport_.call_context()) == it->second
			? auth_state::succeeded : auth_state::failed;
}

void server_test_auth_service::auth_succeeded(auth_context const& context) {
	transport_.log().log(logger::info, "auth succeeded");
}

}
