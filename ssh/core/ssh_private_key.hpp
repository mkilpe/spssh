#ifndef SP_SHH_PRIVATE_KEY_HEADER
#define SP_SHH_PRIVATE_KEY_HEADER

#include "ssh_public_key.hpp"

namespace securepath::ssh {

/** \brief SSH Private Key that is used for Client authentication and Server host key
 */
class ssh_private_key {
public:
	ssh_key_type type() const;

private:
	ssh_key_type type_{ssh_key_type::unknown};
	std::vector<std::byte> data_;
};

}

#endif
