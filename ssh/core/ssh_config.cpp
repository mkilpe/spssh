
#include "ssh_config.hpp"

namespace securepath::ssh {

std::vector<std::string_view> ssh_config::host_key_list() const {
	std::vector<std::string_view> res;
	res.reserve(host_keys.size());
	for(auto&& v : host_keys) {
		res.push_back(to_string(v.type()));
	}
	return res;
}

}

