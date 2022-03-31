
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/mac.hpp"
#include <memory>

namespace securepath::ssh::nettle {

std::unique_ptr<ssh::mac> create_mac(mac_type, const_span const& secret, crypto_call_context const&) {
	return nullptr;
}

}


