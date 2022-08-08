
#include "random.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/private_key.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/ids.hpp"
#include <memory>

#include <cryptopp/eccrypto.h>
#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/xed25519.h>

namespace securepath::ssh::cryptopp {

std::shared_ptr<ssh::public_key> create_public_key(public_key_data const&, crypto_call_context const&);

class ed25519_private_key : public private_key {
public:
	ed25519_private_key(ed25519_private_key_data const& d, crypto_call_context call)
	: privkey_(d.privkey.begin(), d.privkey.end())
	, call_(call)
	{
		if(d.pubkey) {
			pubkey_.insert(pubkey_.end(), d.pubkey->begin(), d.pubkey->end());
			signer_ = std::make_unique<CryptoPP::ed25519Signer>(to_uint8_ptr(pubkey_), to_uint8_ptr(privkey_));
		} else {
			signer_ = std::make_unique<CryptoPP::ed25519Signer>(to_uint8_ptr(privkey_));
			pubkey_.resize(ed25519_key_size);

			// todo: set pubkey_ to contain the public key from signer_
		}
	}

	ed25519_private_key(private_key_info const&, crypto_call_context call)
	: call_(call)
	{
		privkey_.resize(ed25519_key_size);
		pubkey_.resize(ed25519_key_size);
		call.rand.random_bytes(privkey_);
		signer_ = std::make_unique<CryptoPP::ed25519Signer>(to_uint8_ptr(privkey_));

		// todo: set pubkey_ to contain the public key from signer_
	}

	key_type type() const override {
		return key_type::ssh_ed25519;
	}

	std::shared_ptr<ssh::public_key> public_key() const override {
		ed25519_public_key_data data{pubkey_};
		return create_public_key(data, call_);
	}

	std::size_t signature_size() const override {
		return CryptoPP::ed25519Signer::SIGNATURE_LENGTH;
	}

	bool sign(const_span in, span out) const override {
		SPSSH_ASSERT(out.size() >= CryptoPP::ed25519Signer::SIGNATURE_LENGTH, "not enough size for signature");

		return signer_->SignMessage(random_generator(), to_uint8_ptr(in), in.size(), to_uint8_ptr(out));
	}

	bool fill_data(private_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<ed25519_private_key_data&>(data);
			d.privkey = privkey_;
			d.pubkey = pubkey_;
		}
		return ret;
	}

private:
	byte_vector pubkey_;
	byte_vector privkey_;
	crypto_call_context call_;
	std::unique_ptr<CryptoPP::ed25519Signer> signer_;
};

static void extract_rand(void *ctx, size_t length, uint8_t *dst) {
	random& r = *(random*)ctx;
	r.random_bytes(span((std::byte*)dst, length));
}

class rsa_private_key : public private_key {
public:
	rsa_private_key(rsa_private_key_data const& d, crypto_call_context const& call)
	: call_(call)
	, e_(d.e.data.begin(), d.e.data.end())
	, n_(d.n.data.begin(), d.n.data.end())
	, d_(d.d.data.begin(), d.d.data.end())
	, p_(d.p.data.begin(), d.p.data.end())
	, q_(d.q.data.begin(), d.q.data.end())
	{

	}

	rsa_private_key(private_key_info const& info, crypto_call_context const& call)
	: call_(call)
	{

	}

	~rsa_private_key() {

	}

	bool valid() const {
		return is_valid_;
	}

	key_type type() const override {
		return key_type::ssh_rsa;
	}

	std::shared_ptr<ssh::public_key> public_key() const override {
		rsa_public_key_data data{to_umpint(e_), to_umpint(n_)};
		return create_public_key(data, call_);
	}

	std::size_t signature_size() const override {
		//return public_key_.size;
		return 0;
	}

	bool sign(const_span in, span out) const override {
		SPSSH_ASSERT(out.size() >= signature_size(), "not enough size for signature");

		return false;
	}

	bool fill_data(private_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<rsa_private_key_data&>(data);
			d.e.data = const_span(e_);
			d.n.data = const_span(n_);
			d.d.data = const_span(d_);
			d.p.data = const_span(p_);
			d.q.data = const_span(q_);
		}
		return ret;
	}

private:
	crypto_call_context call_;
	bool is_valid_{};

	// these are kept for fill_data and constructing public key
	byte_vector e_;
	byte_vector n_;
	byte_vector d_;
	byte_vector p_;
	byte_vector q_;
};


class ecdsa_private_key : public private_key {
public:
	ecdsa_private_key(ecdsa_private_key_data const& d, crypto_call_context const& call)
	: call_(call)
	, type_(d.ecdsa_type)
	, ecc_point_(d.ecc_point.begin(), d.ecc_point.end())
	, priv_key_(d.privkey.data.begin(), d.privkey.data.end())
	{
	}

	ecdsa_private_key(private_key_info const& info, crypto_call_context const& call)
	: call_(call)
	, is_valid_(true)
	, type_(info.type)
	{

	}

	~ecdsa_private_key() {
	}

	bool valid() const {
		return is_valid_;
	}

	key_type type() const override {
		return type_;
	}

	std::shared_ptr<ssh::public_key> public_key() const override {
		ecdsa_public_key_data data{type_, ecc_point_};
		return create_public_key(data, call_);
	}

	std::size_t signature_size() const override {
		return 64;
	}

	bool sign(const_span in, span out) const override {
		SPSSH_ASSERT(out.size() >= signature_size(), "not enough size for signature");

		return true;
	}

	bool fill_data(private_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<ecdsa_private_key_data&>(data);
			d.ecdsa_type = type_;
			d.ecc_point = ecc_point_;
			d.privkey.data = const_span(priv_key_);
		}
		return ret;
	}

private:
	crypto_call_context call_;
	bool is_valid_{};
	key_type type_;
	byte_vector ecc_point_;
	byte_vector priv_key_;
};


std::shared_ptr<ssh::private_key> create_private_key(private_key_data const& d, crypto_call_context const& call) {
	if(d.type() == key_type::ssh_ed25519) {
		return std::make_shared<ed25519_private_key>(static_cast<ed25519_private_key_data const&>(d), call);
	} else if(d.type() == key_type::ssh_rsa) {
		auto key = std::make_shared<rsa_private_key>(static_cast<rsa_private_key_data const&>(d), call);
		if(key->valid()) {
			return key;
		}
	} else if(d.type() == key_type::ecdsa_sha2_nistp256) {
		auto key = std::make_shared<ecdsa_private_key>(static_cast<ecdsa_private_key_data const&>(d), call);
		if(key->valid()) {
			return key;
		}
	}
	return nullptr;
}

std::shared_ptr<ssh::private_key> generate_private_key(private_key_info const& info, crypto_call_context const& call) {
	if(info.type == key_type::ssh_ed25519) {
		return std::make_shared<ed25519_private_key>(info, call);
	} else if(info.type == key_type::ssh_rsa) {
		auto key = std::make_shared<rsa_private_key>(info, call);
		if(key->valid()) {
			return key;
		}
	} else if(info.type == key_type::ecdsa_sha2_nistp256) {
		auto key = std::make_shared<ecdsa_private_key>(info, call);
		if(key->valid()) {
			return key;
		}
	}
	return nullptr;
}

}
