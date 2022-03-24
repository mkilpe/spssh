#ifndef SP_SHH_KEX_HEADER
#define SP_SHH_KEX_HEADER

#include "ssh_layer.hpp"

#include <string_view>
#include <vector>

namespace securepath::ssh {

enum class kex_type {
	unknown = 0,
	dh_group14_sha256,
	curve25519_sha256,
	ecdh_sha2_nistp256
};

std::string_view to_string(kex_type);
kex_type kex_type_from_string(std::string_view);

struct kex_init_data {
	ssh_version local_ver;
	ssh_version remote_ver;
	std::vector<std::byte> local_kexinit;
	std::vector<std::byte> remote_kexinit;
};

class kex : public ssh_layer {
public:
	virtual ~kex() = default;

	// interface to get kex result data
};

}

#endif
