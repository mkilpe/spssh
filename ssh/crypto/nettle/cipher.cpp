
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/cipher.hpp"
#include "ssh/crypto/ids.hpp"
#include <memory>

namespace securepath::ssh::nettle {

std::unique_ptr<ssh::cipher> create_cipher(cipher_type type, crypto_call_context const&) {
	return nullptr;
}


}
