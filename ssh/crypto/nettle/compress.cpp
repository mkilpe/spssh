
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/compress.hpp"
#include <memory>

namespace securepath::ssh::nettle {

std::unique_ptr<ssh::compress> create_compress(compress_type, crypto_call_context const&) {
	return nullptr;
}

}


