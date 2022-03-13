
#include "ssh_public_key.hpp"

namespace securepath::ssh {

key_type ssh_public_key::type() const {
	return type_;
}

}
