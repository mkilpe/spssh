
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/ids.hpp"
#include <memory>

#include <nettle/eddsa.h>

namespace securepath::ssh::nettle {

class ed25519_public_key : public public_key {
public:
	ed25519_public_key(ed25519_public_key_data const& d)
	: pubkey_(d.pubkey.begin(), d.pubkey.end())
	{
	}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	bool verify(const_span msg, const_span signature) const override {
		if(signature.size() != ED25519_SIGNATURE_SIZE) {
			return false;
		}

		return nettle_ed25519_sha512_verify(
			to_uint8_ptr(pubkey_),
			msg.size(),
			to_uint8_ptr(msg),
			to_uint8_ptr(signature) ) == 1;
	}

private:
	std::vector<std::byte> pubkey_;
};

std::unique_ptr<ssh::public_key> create_public_key(public_key_data const& d, crypto_call_context const&) {
	if(d.type() == key_type::ssh_ed25519) {
		return std::make_unique<ed25519_public_key>(static_cast<ed25519_public_key_data const&>(d));
	}
	return nullptr;
}

}

