
#include "random.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/key_exchange.hpp"

#include <cryptopp/xed25519.h>

namespace securepath::ssh::cryptopp {

class X25519_key_exchange : public key_exchange {
public:
	X25519_key_exchange(crypto_call_context const& c)
	: context(c)
	, exchange_(random_generator())
	{
		context.log.log(logger::debug_trace, "constructing X25519_key_exchange");

		privkey_.resize(exchange_.PrivateKeyLength());
		pubkey_.resize(exchange_.PublicKeyLength());
		exchange_.GenerateKeyPair(random_generator(), to_uint8_ptr(privkey_), to_uint8_ptr(pubkey_));
	}

	key_exchange_type type() const override {
		return key_exchange_type::X25519;
	}

	const_span public_key() const override {
		return pubkey_;
	}

	byte_vector agree(const_span remote_public) override {
		if(remote_public.size() != exchange_.PublicKeyLength()) {
			return {};
		}

		byte_vector res(exchange_.AgreedValueLength());
		if(!exchange_.Agree(to_uint8_ptr(res), to_uint8_ptr(privkey_), to_uint8_ptr(remote_public))) {
			return {};
		}

		return res;
	}

	crypto_call_context context;
	byte_vector privkey_;
	byte_vector pubkey_;
	CryptoPP::x25519 exchange_;

};

std::unique_ptr<ssh::key_exchange> create_key_exchange(key_exchange_data const& d, crypto_call_context const& c) {
	if(d.type() == key_exchange_type::X25519) {
		return std::make_unique<X25519_key_exchange>(c);
	}
	return nullptr;
}

}

