
#include "ssh_config.hpp"
#include "util.hpp"

namespace securepath::ssh {

bool ssh_config::valid() const {
	return algorithms.valid();
}

bool ssh_config::set_host_keys_for_server(std::vector<ssh_private_key> keys) {
	for(auto&& k : keys) {
		if(!add_private_key(k)) {
			algorithms.host_keys.add_back(k.type());
			private_keys.clear();
			return false;
		}
	}
	return true;
}

bool ssh_config::add_private_key(ssh_private_key k) {
	auto ser_pubkey = to_byte_vector(k.public_key());
	bool ret = !ser_pubkey.empty();
	if(ret) {
		private_keys.emplace_back(std::move(k), std::move(ser_pubkey));
	}
	return ret;
}

}

