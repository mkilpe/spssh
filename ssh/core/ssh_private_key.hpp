#ifndef SP_SHH_PRIVATE_KEY_HEADER
#define SP_SHH_PRIVATE_KEY_HEADER

#include "ssh_public_key.hpp"
#include "ssh/crypto/private_key.hpp"
#include <memory>

namespace securepath::ssh {

/** \brief SSH Private Key that is used for Client authentication and Server host key
 */
class ssh_private_key {
public:
	ssh_private_key() = default;
	ssh_private_key(std::unique_ptr<private_key>);

	key_type type() const;

private:
	std::unique_ptr<private_key> key_impl_;
};

}

#endif
