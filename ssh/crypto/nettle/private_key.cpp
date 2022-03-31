
#include "util.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/ids.hpp"

#include <memory>

#include <nettle/eddsa.h>

namespace securepath::ssh::nettle {

std::unique_ptr<ssh::public_key> create_public_key(public_key_data const&, crypto_call_context const&);

class ed25519_private_key : public private_key {
public:
	ed25519_private_key(ed25519_private_key_data const& d, crypto_call_context call)
	: privkey_(d.privkey.begin(), d.privkey.end())
	, call_(call)
	{
		if(d.pubkey) {
			pubkey_.insert(pubkey_.end(), d.pubkey->begin(), d.pubkey->end());
		} else {
			pubkey_.resize(ed25519_key_size);
			nettle_ed25519_sha512_public_key(to_uint8_ptr(pubkey_), to_uint8_ptr(privkey_));
		}
	}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	std::unique_ptr<ssh::public_key> public_key() const override {
		ed25519_public_key_data data{ed25519_public_key_data::value_type(pubkey_.data(), pubkey_.size())};
		return create_public_key(data, call_);
	}

	std::size_t signature_size() const override {
		return ED25519_SIGNATURE_SIZE;
	}

	void sign(const_span in, span out) const override {
		SPSSH_ASSERT(out.size() >= ED25519_SIGNATURE_SIZE, "not enough size for signature");

		nettle_ed25519_sha512_sign(
			to_uint8_ptr(pubkey_),
			to_uint8_ptr(privkey_),
			in.size(),
			to_uint8_ptr(in),
			to_uint8_ptr(out) );
	}

private:
	std::vector<std::byte> pubkey_;
	std::vector<std::byte> privkey_;
	crypto_call_context call_;
};

std::unique_ptr<ssh::private_key> create_private_key(private_key_data const& d, crypto_call_context const& call) {
	if(d.type() == key_type::ssh_ed25519) {
		return std::make_unique<ed25519_private_key>(static_cast<ed25519_private_key_data const&>(d), call);
	}
	return nullptr;
}

}
