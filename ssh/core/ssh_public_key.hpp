#ifndef SP_SHH_PUBLIC_KEY_HEADER
#define SP_SHH_PUBLIC_KEY_HEADER

#include "ssh/crypto/ids.hpp"

#include <vector>

namespace securepath::ssh {

/** \brief SSH Public Key that is used for signature checking
 */
class ssh_public_key {
public:
	ssh_public_key() = default;

	key_type type() const;

private:
	key_type type_{key_type::unknown};
	std::vector<std::byte> data_;
};

}

#endif
