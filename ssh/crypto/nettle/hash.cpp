
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/hash.hpp"
#include <memory>

#include <nettle/sha2.h>

namespace securepath::ssh::nettle {

class sha2_256_hash : public hash {
public:
	sha2_256_hash()
	: hash(SHA256_DIGEST_SIZE)
	{
		nettle_sha256_init(&ctx_);
	}

	void process(const_span in) override {
		nettle_sha256_update(&ctx_, in.size(), to_uint8_ptr(in));
	}

	void digest(span out) override {
		SPSSH_ASSERT(out.size() >= SHA256_DIGEST_SIZE, "invalid out buffer size");
		std::size_t size = std::min<std::size_t>(SHA256_DIGEST_SIZE, out.size());
		nettle_sha256_digest(&ctx_, size, to_uint8_ptr(out));
	}

private:
	sha256_ctx ctx_;
};


class sha2_512_hash : public hash {
public:
	sha2_512_hash()
	: hash(SHA512_DIGEST_SIZE)
	{
		nettle_sha512_init(&ctx_);
	}

	void process(const_span in) override {
		nettle_sha512_update(&ctx_, in.size(), to_uint8_ptr(in));
	}

	void digest(span out) override {
		SPSSH_ASSERT(out.size() >= SHA512_DIGEST_SIZE, "invalid out buffer size");
		std::size_t size = std::min<std::size_t>(SHA512_DIGEST_SIZE, out.size());
		nettle_sha512_digest(&ctx_, size, to_uint8_ptr(out));
	}

private:
	sha512_ctx ctx_;
};


std::unique_ptr<ssh::hash> create_hash(hash_type t, crypto_call_context const&) {
	using enum hash_type;
	if(t == sha2_256) {
		return std::make_unique<sha2_256_hash>();
	} else if(t == sha2_512) {
		return std::make_unique<sha2_512_hash>();
	}
	return nullptr;
}

}


