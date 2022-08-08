
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/mac.hpp"
#include <memory>

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

namespace securepath::ssh::cryptopp {

class hmac_sha2_256 : public mac {
public:
	using hmac = CryptoPP::HMAC<CryptoPP::SHA256>;

	hmac_sha2_256(const_span secret)
	: mac(hmac::DIGESTSIZE)
	, mac_(to_uint8_ptr(secret), secret.size())
	{
	}

	/// feed data to calculate message authentication code
	void process(const_span in) override {
		mac_.Update(to_uint8_ptr(in), in.size());
	}

	/// output mac and reset the mac accumulation
	void result(span out) override {
		SPSSH_ASSERT(out.size() >= hmac::DIGESTSIZE, "invalid out buffer size");
		mac_.Final(to_uint8_ptr(out));
	}

private:
	hmac mac_;
};

std::unique_ptr<ssh::mac> create_mac(mac_type type, const_span secret, crypto_call_context const&) {
	if(type == mac_type::hmac_sha2_256) {
		return std::make_unique<hmac_sha2_256>(secret);
	}
	return nullptr;
}

}


