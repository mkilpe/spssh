
#include "random.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/ids.hpp"
#include "ssh/crypto/key_exchange.hpp"

#include <cryptopp/dh.h>
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

class dh_key_exchange : public key_exchange {
public:
	dh_key_exchange(key_exchange_type t, crypto_call_context const& c, CryptoPP::Integer const& modulus, CryptoPP::Integer const& generator)
	: context(c)
	, type_(t)
	, exchange_(modulus, generator)
	, privkey_(exchange_.PrivateKeyLength())
	, pubkey_(exchange_.PublicKeyLength())
	{
		context.log.log(logger::debug_trace, "constructing dh_key_exchange");

		is_valid_ = exchange_.GetGroupParameters().ValidateGroup(random_generator(), 3);
		if(is_valid_) {
			exchange_.GenerateKeyPair(random_generator(), to_uint8_ptr(privkey_), to_uint8_ptr(pubkey_));
		}
	}

	template<typename Modp>
	dh_key_exchange(key_exchange_type t, crypto_call_context const& c, Modp const& m)
	: dh_key_exchange(t, c, m.modulus(), m.generator())
	{
	}

	bool is_valid() const {
		return is_valid_;
	}

	key_exchange_type type() const override {
		return type_;
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
	key_exchange_type type_;
	bool is_valid_{};
	CryptoPP::DH exchange_;
	byte_vector privkey_;
	byte_vector pubkey_;
};

// 2048-bit MODP Group from RFC 3526
struct modp_group_14 {
	static auto modulus() {
		auto m = modp_group_14_modulus();
		return CryptoPP::Integer(to_uint8_ptr(m), m.size());
	}

	static auto generator() {
		auto g = modp_group_14_generator();
		return CryptoPP::Integer(to_uint8_ptr(g), g.size());
	}
};

// 4096-bit MODP Group from RFC 3526
struct modp_group_16 {
	static auto modulus() {
		auto m = modp_group_16_modulus();
		return CryptoPP::Integer(to_uint8_ptr(m), m.size());
	}

	static auto generator() {
		auto g = modp_group_16_generator();
		return CryptoPP::Integer(to_uint8_ptr(g), g.size());
	}
};

std::unique_ptr<ssh::key_exchange> create_key_exchange(key_exchange_data const& d, crypto_call_context const& call) {
	try {
		if(d.type() == key_exchange_type::X25519) {
			return std::make_unique<X25519_key_exchange>(call);
		} else if(d.type() == key_exchange_type::dh_group14) {
			auto p = std::make_unique<dh_key_exchange>(d.type(), call, modp_group_14{});
			if(p->is_valid()) {
				return p;
			}
		} else if(d.type() == key_exchange_type::dh_group16) {
			auto p = std::make_unique<dh_key_exchange>(d.type(), call, modp_group_16{});
			if(p->is_valid()) {
				return p;
			}
		}
	} catch(CryptoPP::Exception const& ex) {
		call.log.log(logger::error, "cryptopp exception: {}", ex.what());
	}
	return nullptr;
}

}

