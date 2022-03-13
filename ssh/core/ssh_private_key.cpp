#include "ssh_private_key.hpp"

#include "ssh/crypto/private_key.hpp"

namespace securepath::ssh {

ssh_private_key::ssh_private_key(std::unique_ptr<private_key> i)
: key_impl_(std::move(i))
{
}

key_type ssh_private_key::type() const {
	return key_impl_ ? key_impl_->type() : key_type::unknown;
}

}
