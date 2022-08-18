
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/mac.hpp"
#include <memory>

#include <nettle/hmac.h>

namespace securepath::ssh::nettle {

class hmac_sha2_256 : public mac {
public:
	hmac_sha2_256(const_span secret)
	: mac(SHA256_DIGEST_SIZE)
	{
		nettle_hmac_sha256_set_key(&ctx_, secret.size(), to_uint8_ptr(secret));
	}

	/// feed data to calculate message authentication code
	void process(const_span in) override {
		nettle_hmac_sha256_update(&ctx_, in.size(), to_uint8_ptr(in));
	}

	/// output mac and reset the mac accumulation
	void result(span out) override {
		std::size_t size = std::min<std::size_t>(SHA256_DIGEST_SIZE, out.size());
		nettle_hmac_sha256_digest(&ctx_, size, to_uint8_ptr(out));
	}

private:
	hmac_sha256_ctx ctx_;
};

std::unique_ptr<ssh::mac> create_mac(mac_type type, const_span secret, crypto_call_context const&) {
	if(type == mac_type::hmac_sha2_256) {
		return std::make_unique<hmac_sha2_256>(secret);
	}
	return nullptr;
}

}


