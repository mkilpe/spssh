
#include "server_auth_service.hpp"

#include <algorithm>

namespace securepath::ssh {


void test_auth_data::add_password(std::string const& user, std::string password) {
	passwords[user] = std::move(password);
}

void test_auth_data::add_pk(std::string const& user, std::string fp) {
	pk_fingerprints[user] = std::move(fp);
}

void test_auth_data::add_host(std::string const& user, std::string fp, std::string domain, std::string host_user) {
	std::transform(domain.begin(), domain.end(), domain.begin(), [](auto c){ return std::tolower(c); });
	hosts[user]	= test_host_data{fp, domain, host_user};
}

void test_auth_data::add_interactive(std::string const& user, std::vector<interactive_request> req, std::vector<std::vector<std::string>> res) {
	interactives[user] = test_interactive_data{std::move(req), std::move(res)};
}

server_test_auth_service::server_test_auth_service(transport_base& transport, auth_config const& config, test_auth_data data)
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

auth_state server_test_auth_service::verify_host(auth_context const& context, ssh_public_key const& pk, std::string_view fqdn, std::string_view host_user) {
	std::string domain(fqdn);
	std::transform(domain.begin(), domain.end(), domain.begin(), [](auto c){ return std::tolower(c); });

	auto it = data_.hosts.find(context.username);
	return it != data_.hosts.end()
		&& pk.fingerprint(transport_.crypto(), transport_.call_context()) == it->second.fingerprint
		&& domain == it->second.domain
		&& host_user == it->second.host_user
			? auth_state::succeeded : auth_state::failed;
}

auth_state server_test_auth_service::start_interactive(auth_context const& context, std::vector<std::string_view> const& submethods, interactive_request& request) {
	interactive_state = 0;
	auto it = data_.interactives.find(context.username);
	bool found = it != data_.interactives.end();
	if(found) {
		if(!it->second.requests.empty()) {
			request = it->second.requests[0];
		}
	}
	return found ? auth_state::succeeded : auth_state::failed;
}

// needed to compare vector of strings to a vector of string_views
template<typename C1, typename C2>
static bool equal(C1 const& c1, C2 const& c2) {
	return std::equal(c1.begin(), c1.end(), c2.begin(), c2.end(),
		[](auto const& v1, auto const& v2) {
			return v1 == v2;
		});
}

auth_interactive_state server_test_auth_service::verify_interactive(auth_context const& context, std::vector<std::string_view> const& responses) {
	auto it = data_.interactives.find(context.username);
	if(it != data_.interactives.end()) {
		if(it->second.responses.size() <= interactive_state) {
			interactive_state = 0;
			return auth_interactive_state::failed;
		}
		if(equal(responses, it->second.responses[interactive_state])) {
			++interactive_state;
			if(interactive_state >= it->second.requests.size()) {
				return auth_interactive_state::succeeded;
			} else {
				send_interactive_request(it->second.requests[interactive_state]);
				return auth_interactive_state::more;
			}
		}
	}
	return auth_interactive_state::failed;
}

void server_test_auth_service::auth_succeeded(auth_context const& context) {
	transport_.log().log(logger::info, "auth succeeded");
}

}
