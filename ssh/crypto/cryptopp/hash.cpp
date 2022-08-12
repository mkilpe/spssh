
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/hash.hpp"
#include <memory>

#include <cryptopp/sha.h>

namespace securepath::ssh::cryptopp {

class sha2_256_hash : public hash {
public:
	sha2_256_hash()
	: hash(CryptoPP::SHA256::DIGESTSIZE)
	{
	}

	void process(const_span in) override {
		hash_.Update(to_uint8_ptr(in), in.size());
	}

	void digest(span out) override {
		SPSSH_ASSERT(out.size() >= CryptoPP::SHA256::DIGESTSIZE, "invalid out buffer size");
		hash_.Final(to_uint8_ptr(out));
	}

private:
	CryptoPP::SHA256 hash_;
};

class sha2_512_hash : public hash {
public:
	sha2_512_hash()
	: hash(CryptoPP::SHA512::DIGESTSIZE)
	{
	}

	void process(const_span in) override {
		hash_.Update(to_uint8_ptr(in), in.size());
	}

	void digest(span out) override {
		SPSSH_ASSERT(out.size() >= CryptoPP::SHA512::DIGESTSIZE, "invalid out buffer size");
		hash_.Final(to_uint8_ptr(out));
	}

private:
	CryptoPP::SHA512 hash_;
};


std::unique_ptr<ssh::hash> create_hash(hash_type t, crypto_call_context const& call) {
	using enum hash_type;
	try {
		if(t == sha2_256) {
			return std::make_unique<sha2_256_hash>();
		} else if(t == sha2_512) {
			return std::make_unique<sha2_512_hash>();
		}
	} catch(CryptoPP::Exception const& ex) {
		call.log.log(logger::error, "cryptopp exception: {}", ex.what());
	}
	return nullptr;
}

}


