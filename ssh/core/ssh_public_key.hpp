#ifndef SP_SHH_PUBLIC_KEY_HEADER
#define SP_SHH_PUBLIC_KEY_HEADER

#include "ssh/common/types.hpp"

#include <vector>

namespace securepath::ssh {

enum class ssh_key_type {
	unknown = 0,
	ssh_rsa,
	ssh_ed25519,
	ecdsa_sha2_nistp256
};

std::string_view to_string(ssh_key_type);
ssh_key_type ssh_key_type_from_string(std::string_view);

/** \brief SSH Public Key that is used for signature checking
 */
class ssh_public_key {
public:
	ssh_key_type type() const;

private:
	ssh_key_type type_{ssh_key_type::unknown};
	std::vector<std::byte> data_;
};

}

#endif
