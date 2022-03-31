
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/cipher.hpp"
#include "ssh/crypto/ids.hpp"
#include <memory>

#include <nettle/gcm.h>

namespace securepath::ssh::nettle {


class aes256_gcm_cipher : public aead_cipher {
public:
	aes256_gcm_cipher(cipher_dir dir, const_span secret)
	: aead_cipher(GCM_BLOCK_SIZE, GCM_DIGEST_SIZE)
	, dir_(dir)
	, key_(secret.begin(), secret.end())
	{
		nettle_gcm_aes256_set_key(&ctx_, to_uint8_ptr(key_));
		nettle_gcm_aes256_set_iv(&ctx_, GCM_IV_SIZE, to_uint8_ptr(iv_));
	}

	bool process(const_span in, span out) override {
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
		nettle_gcm_aes256_digest(&ctx_, out.size(), to_uint8_ptr(out));
	}

private:
	cipher_dir const dir_;
	gcm_aes256_ctx ctx_;
	std::vector<std::byte> key_;
};

std::unique_ptr<ssh::cipher> create_cipher(cipher_type t, const_span const& secret, cipher_dir dir, crypto_call_context const&) {
	using enum cipher_type;
	if(t == aes_256_gcm) {
		return std::make_unique<aes256_gcm_cipher>(dir, secret);
	}
	return nullptr;
}


}
