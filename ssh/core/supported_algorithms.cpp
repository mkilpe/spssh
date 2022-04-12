#include "supported_algorithms.hpp"

#include "ssh/common/logger.hpp"

namespace securepath::ssh {

bool supported_algorithms::valid() const {
	return !host_keys.empty()
		&& !kexes.empty()
		&& !client_server_ciphers.empty()
		&& !server_client_ciphers.empty()
		&& !client_server_macs.empty()
		&& !server_client_macs.empty()
		&& !client_server_compress.empty()
		&& !server_client_compress.empty();
}

void supported_algorithms::dump(std::string_view tag, logger& l) const {
	l.log(logger::debug_verbose, "{}: supported_algorithms:\n"
		"\thost_keys={}\n"
		"\tkexes={}\n"
		"\tclient_server_ciphers={}\n"
		"\tserver_client_ciphers={}\n"
		"\tclient_server_macs={}\n"
		"\tserver_client_macs={}\n"
		"\tclient_server_compress={}\n"
		"\tserver_client_compress={}",
		tag,
		host_keys.name_list_string(), kexes.name_list_string(), client_server_ciphers.name_list_string(),
		server_client_ciphers.name_list_string(), client_server_macs.name_list_string(), server_client_macs.name_list_string(),
		client_server_compress.name_list_string(), server_client_compress.name_list_string());
}

}

