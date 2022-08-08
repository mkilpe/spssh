
#include "random.hpp"
#include "ssh/crypto/crypto_call_context.hpp"
#include "ssh/crypto/public_key.hpp"
#include "ssh/crypto/ids.hpp"
#include <memory>

#include <cryptopp/eccrypto.h>
#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/xed25519.h>

namespace securepath::ssh::cryptopp {

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
		if(signature.size() != CryptoPP::ed25519Verifier::SIGNATURE_LENGTH) {
			return false;
		}

		CryptoPP::ed25519Verifier ver(to_uint8_ptr(pubkey_));
		return ver.VerifyMessage(to_uint8_ptr(msg), msg.size(), to_uint8_ptr(signature), signature.size());
	}

	bool fill_data(public_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<ed25519_public_key_data&>(data);
			d.pubkey = const_span(pubkey_);
		}
		return ret;
	}

private:
	byte_vector pubkey_;
};


class rsa_public_key : public public_key {
public:
	rsa_public_key(rsa_public_key_data const& d)
	: e_(d.e.data.begin(), d.e.data.end())
	, n_(d.n.data.begin(), d.n.data.end())
	{
		CryptoPP::Integer e(to_uint8_ptr(e_), e_.size());
		CryptoPP::Integer n(to_uint8_ptr(n_), n_.size());

		rsa_pubkey_.Initialize(n, e);
		is_valid_ = rsa_pubkey_.Validate(random_generator(), 3);;
	}

	~rsa_public_key() {
	}

	bool valid() const {
		return is_valid_;
	}

	key_type type() const override {
		return key_type::ssh_rsa;
	}

	bool verify(const_span in, const_span signature) const override {
		CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Verifier ver(rsa_pubkey_);
		return ver.VerifyMessage(to_uint8_ptr(in), in.size(), to_uint8_ptr(signature), signature.size());
	}

	bool fill_data(public_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<rsa_public_key_data&>(data);
			d.e.data = const_span(e_);
			d.n.data = const_span(n_);
		}
		return ret;
	}

private:
	bool is_valid_{};
	byte_vector e_;
	byte_vector n_;

	CryptoPP::RSA::PublicKey rsa_pubkey_;
};


class ecdsa_public_key : public public_key {
public:
	ecdsa_public_key(ecdsa_public_key_data const& d, crypto_call_context const& call)
	: type_(d.ecdsa_type)
	, pubkey_(d.ecc_point.begin(), d.ecc_point.end())
	{
		// see the size is correct and it is uncompressed ecc point, otherwise don't bother
		if(d.ecc_point.size() == 65 && d.ecc_point[0] == std::byte{0x04}) {
			CryptoPP::ECP::Point q;
			q.identity = false;
			q.x.Decode(to_uint8_ptr(d.ecc_point)+1, 32);
			q.y.Decode(to_uint8_ptr(d.ecc_point)+33, 32);

			ecdsa_pubkey_.Initialize(CryptoPP::ASN1::secp256r1(), q);
			is_valid_ = ecdsa_pubkey_.Validate(random_generator(), 3);
		}
	}

	~ecdsa_public_key() {
	}

	bool valid() const {
		return is_valid_;
	}

	key_type type() const override {
		return type_;
	}

	bool verify(const_span msg, const_span signature) const override {
		if(signature.size() != 64) {
			return false;
		}

		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier ver(ecdsa_pubkey_);
		return ver.VerifyMessage(to_uint8_ptr(msg), msg.size(), to_uint8_ptr(signature), signature.size());
	}

	bool fill_data(public_key_data& data) const override {
		bool ret = data.type() == type();
		if(ret) {
			auto& d = static_cast<ecdsa_public_key_data&>(data);
			d.ecc_point = const_span(pubkey_);
		}
		return ret;
	}

private:
	bool is_valid_{};
	key_type type_;
	byte_vector pubkey_;
	CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey ecdsa_pubkey_;
};


std::shared_ptr<ssh::public_key> create_public_key(public_key_data const& d, crypto_call_context const& call) {
	if(d.type() == key_type::ssh_ed25519) {
		return std::make_shared<ed25519_public_key>(static_cast<ed25519_public_key_data const&>(d));
	} else if(d.type() == key_type::ssh_rsa) {
		auto key = std::make_shared<rsa_public_key>(static_cast<rsa_public_key_data const&>(d));
		if(key->valid()) {
			return key;
		}
	} else if(d.type() == key_type::ecdsa_sha2_nistp256) {
		auto key = std::make_shared<ecdsa_public_key>(static_cast<ecdsa_public_key_data const&>(d), call);
		if(key->valid()) {
			return key;
		}
	}
	return nullptr;
}

}

