
#include "ssh/common/util.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/cipher.hpp"
#include "ssh/crypto/ids.hpp"
#include <memory>

#include <nettle/gcm.h>

namespace securepath::ssh::nettle {

static_assert(GCM_IV_SIZE == 12, "invalid iv size");

class aes256_gcm_cipher : public aead_cipher {
public:
	aes256_gcm_cipher(cipher_dir dir, const_span secret, const_span iv, crypto_call_context const& call)
	: aead_cipher(GCM_BLOCK_SIZE, GCM_DIGEST_SIZE)
	, call_(call)
	, dir_(dir)
	, key_(secret.begin(), secret.end())
	{
		SPSSH_ASSERT(iv.size() == 12, "invalid iv size");
		SPSSH_ASSERT(key_.size() == 32, "invalid key size");

		std::memcpy(iv_, iv.data(), 12);

		nettle_gcm_aes256_set_key(&ctx_, to_uint8_ptr(key_));
		nettle_gcm_aes256_set_iv(&ctx_, GCM_IV_SIZE, iv_);
	}

	bool process(const_span in, span out) override {
		SPSSH_ASSERT(same_source_or_non_overlapping(in, out), "invalid in/out");
		if(in.size() <= out.size()) {
			if(dir_ == cipher_dir::encrypt) {
				nettle_gcm_aes256_encrypt(&ctx_, in.size(), to_uint8_ptr(out), to_uint8_ptr(in));
			} else {
				nettle_gcm_aes256_decrypt(&ctx_, in.size(), to_uint8_ptr(out), to_uint8_ptr(in));
			}
			return true;
		}
		return false;
	}

	void process_auth(const_span in) override {
		nettle_gcm_aes256_update(&ctx_, in.size(), to_uint8_ptr(in));
	}

	void tag(span out) override {
		SPSSH_ASSERT(out.size() == GCM_DIGEST_SIZE, "invalid digest size");

		nettle_gcm_aes256_digest(&ctx_, out.size(), to_uint8_ptr(out));

		//the iv_ is combination of 4 bytes fixed and 8 bytes of invocation counter.
		// the invocation counter is most significant bit first, we increment that counter by one
		int i = sizeof(iv_)-1;
		while(i > 3 && ++iv_[i] == 0) {
			++i;
		}
		nettle_gcm_aes256_set_iv(&ctx_, GCM_IV_SIZE, iv_);
	}

private:
	crypto_call_context call_;

	cipher_dir dir_;
	gcm_aes256_ctx ctx_;
	byte_vector key_;

	//rfc 5647 IV handling
	std::uint8_t iv_[12];
};

std::unique_ptr<ssh::cipher> create_cipher(cipher_type t, cipher_dir dir, const_span const& secret, const_span const& iv, crypto_call_context const& call ) {
	using enum cipher_type;
	if(t == aes_256_gcm || t == openssh_aes_256_gcm) {
		if(secret.size() == 32 && iv.size() == 12) {
			return std::make_unique<aes256_gcm_cipher>(dir, secret, iv, call);
		} else {
			call.log.log(logger::error, "invalid key or iv size of aes_256_gcm");
		}
	}
	return nullptr;
}


}
