#ifndef SP_SHH_KEX_HEADER
#define SP_SHH_KEX_HEADER

#include "ssh_layer.hpp"
#include <string_view>

namespace securepath::ssh {

enum class kex_type {
	unknown = 0,
	dh_group14_sha256,
	curve25519_sha256,
	ecdh_sha2_nistp256
};

std::string_view to_string(kex_type);
kex_type kex_type_from_string(std::string_view);

class kex : public ssh_layer {
public:
	virtual ~kex() = default;

	// interface to get kex result data
};

}

#endif
