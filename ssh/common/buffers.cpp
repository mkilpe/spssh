#include "buffers.hpp"

#include <cstring>

namespace securepath::ssh {

bool out_buffer::write(std::string_view v) {
	span s = get(v.size());
	if(!s.empty()) {
		std::memcpy(s.data(), v.data(), s.size());
		commit(v.size());
	}
	return !s.empty();
}

}

