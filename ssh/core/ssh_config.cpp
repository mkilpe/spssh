
#include "ssh_config.hpp"

namespace securepath::ssh {

bool ssh_config::valid() const {
	return algorithms.valid();
}

void ssh_config::set_host_keys_for_server(std::vector<ssh_private_key> keys) {
	private_keys = std::move(keys);
	for(auto&& k : private_keys) {
		algorithms.host_keys.add_back(k.type());
	}
}

}

