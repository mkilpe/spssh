
#include "ssh/common/util.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/cipher.hpp"
#include "ssh/crypto/ids.hpp"
#include <memory>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/modes.h>

namespace securepath::ssh::cryptopp {

std::size_t const gcm_iv_size = 12;
std::size_t const aes_key_size = 32;

template<typename Cipher>
class aes256_gcm_cipher : public aead_cipher {
public:

	aes256_gcm_cipher(const_span secret, const_span iv, crypto_call_context const& call)
	: aead_cipher(/*GCM_BLOCK_SIZE*/ 16, /*GCM_DIGEST_SIZE*/ 16)
	, call_(call)
	{
		SPSSH_ASSERT(iv.size() == gcm_iv_size, "invalid iv size");
		SPSSH_ASSERT(secret.size() == aes_key_size, "invalid key size");

		cipher_.SetKeyWithIV(to_uint8_ptr(secret), secret.size(), to_uint8_ptr(iv), iv.size());
	}

	bool process(const_span in, span out) override {
		SPSSH_ASSERT(same_source_or_non_overlapping(in, out), "invalid in/out");
		cipher_.ProcessData(to_uint8_ptr(out), to_uint8_ptr(in), in.size());
		return true;
	}

	void process_auth(const_span in) override {
		cipher_.Update(to_uint8_ptr(in), in.size());
	}

	void tag(span out) override {
		SPSSH_ASSERT(out.size() == cipher_.DigestSize(), "invalid digest size");
		cipher_.Final(to_uint8_ptr(out));
	}

private:
	crypto_call_context call_;
	Cipher cipher_;
};

template<typename Cipher>
class aes256_ctr : public cipher {
public:
	aes256_ctr(const_span secret, const_span iv)
	: cipher(CryptoPP::AES::BLOCKSIZE, false)
	, cipher_(to_uint8_ptr(secret), secret.size(), to_uint8_ptr(iv))
	{
	}

	/// encrypt/decrypt, it is possible that the range in == out
	bool process(const_span in, span out) override {
		SPSSH_ASSERT(same_source_or_non_overlapping(in, out), "invalid in/out");
		cipher_.ProcessData(to_uint8_ptr(out), to_uint8_ptr(in), in.size());
		return true;
	}

private:
	Cipher cipher_;
};

std::unique_ptr<ssh::cipher> create_cipher(cipher_type t, cipher_dir dir, const_span secret, const_span iv, crypto_call_context const& call ) {
	using enum cipher_type;
	if(t == aes_256_gcm || t == openssh_aes_256_gcm) {
		if(secret.size() == aes_key_size && iv.size() == gcm_iv_size) {
			if(dir == cipher_dir::encrypt) {
				return std::make_unique<aes256_gcm_cipher<CryptoPP::GCM<CryptoPP::AES>::Encryption>>(secret, iv, call);
			} else {
				return std::make_unique<aes256_gcm_cipher<CryptoPP::GCM<CryptoPP::AES>::Decryption>>(secret, iv, call);
			}
		} else {
			call.log.log(logger::error, "invalid key or iv size of aes_256_gcm");
		}
	} else if(t == aes_256_ctr) {
		if(secret.size() == aes_key_size && iv.size() == 16) {
			if(dir == cipher_dir::encrypt) {
				return std::make_unique<aes256_ctr<CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption>>(secret, iv);
			} else {
				return std::make_unique<aes256_ctr<CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption>>(secret, iv);
			}
		} else {
			call.log.log(logger::error, "invalid key or iv size of aes_256_ctr");
		}
	}
	return nullptr;
}

}
