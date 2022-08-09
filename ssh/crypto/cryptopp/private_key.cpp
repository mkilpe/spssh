
#include "random.hpp"
#include "util.hpp"
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

static void zero_pad(const_span in, std::size_t size, span out) {
	if(in.size() < size && out.size() > in.size()) {
		std::size_t diff = std::min(size - in.size(), out.size() - in.size());
		std::memmove(to_uint8_ptr(out)+diff, to_uint8_ptr(in), in.size());
		std::memset(to_uint8_ptr(out), 0, diff);
	}
}

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

			auto const& pkey = static_cast<CryptoPP::ed25519PrivateKey const&>(signer_->GetPrivateKey());
			copy(const_span{(std::byte const*)pkey.GetPublicKeyBytePtr(), CryptoPP::ed25519PrivateKey::PUBLIC_KEYLENGTH}, pubkey_);
		}
	}

	ed25519_private_key(private_key_info const&, crypto_call_context call)
	: call_(call)
	{
		signer_ = std::make_unique<CryptoPP::ed25519Signer>(random_generator());

		privkey_.resize(ed25519_key_size);
		pubkey_.resize(ed25519_key_size);

		auto const& pkey = static_cast<CryptoPP::ed25519PrivateKey const&>(signer_->GetPrivateKey());
		copy(const_span{(std::byte const*)pkey.GetPrivateKeyBytePtr(), CryptoPP::ed25519PrivateKey::SECRET_KEYLENGTH}, privkey_);
		copy(const_span{(std::byte const*)pkey.GetPublicKeyBytePtr(), CryptoPP::ed25519PrivateKey::PUBLIC_KEYLENGTH}, pubkey_);
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

		std::size_t size = signer_->SignMessage(random_generator(), to_uint8_ptr(in), in.size(), to_uint8_ptr(out));

		if(size < signature_size()) {
			zero_pad(safe_subspan(out, 0, size), signature_size(), out);
		}

		return true;
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
		CryptoPP::Integer rsa_e(to_uint8_ptr(e_), e_.size());
		CryptoPP::Integer rsa_n(to_uint8_ptr(n_), n_.size());
		CryptoPP::Integer rsa_d(to_uint8_ptr(d_), d_.size());
		//CryptoPP::Integer rsa_p(to_uint8_ptr(p_), p_.size());
		//CryptoPP::Integer rsa_q(to_uint8_ptr(q_), q_.size());

		//todo: use the p and q as well to speed things up
		rsa_privkey_.Initialize(rsa_n, rsa_e, rsa_d);
		is_valid_ = rsa_privkey_.Validate(random_generator(), 3);
		if(is_valid_) {
			rsa_signer_ = CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Signer(rsa_privkey_);
		}
	}

	rsa_private_key(private_key_info const& info, crypto_call_context const& call)
	: call_(call)
	, is_valid_(true)
	{
		// we use fixed 65537 as e
		rsa_privkey_.Initialize(random_generator(), info.size, 65537);

		CryptoPP::Integer const& e = rsa_privkey_.GetPublicExponent();
		e_.resize(e.MinEncodedSize());
		e.Encode(to_uint8_ptr(e_), e_.size());

		CryptoPP::Integer const& n = rsa_privkey_.GetModulus();
		n_.resize(n.MinEncodedSize());
		n.Encode(to_uint8_ptr(n_), n_.size());

		CryptoPP::Integer const& d = rsa_privkey_.GetPrivateExponent();
		d_.resize(d.MinEncodedSize());
		d.Encode(to_uint8_ptr(d_), d_.size());

		CryptoPP::Integer const& p = rsa_privkey_.GetPrime1();
		p_.resize(p.MinEncodedSize());
		p.Encode(to_uint8_ptr(p_), p_.size());

		CryptoPP::Integer const& q = rsa_privkey_.GetPrime2();
		q_.resize(q.MinEncodedSize());
		q.Encode(to_uint8_ptr(q_), q_.size());

		rsa_signer_ = CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Signer(rsa_privkey_);
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
		return rsa_signer_.MaxSignatureLength();
	}

	bool sign(const_span in, span out) const override {
		SPSSH_ASSERT(out.size() >= signature_size(), "not enough size for signature");

		std::size_t size = rsa_signer_.SignMessage(random_generator(), to_uint8_ptr(in), in.size(), to_uint8_ptr(out));
		if(size < signature_size()) {
			zero_pad(safe_subspan(out, 0, size), signature_size(), out);
		}

		return true;
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

	CryptoPP::RSA::PrivateKey rsa_privkey_;
	CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Signer rsa_signer_;
};


class ecdsa_private_key : public private_key {
public:
	ecdsa_private_key(ecdsa_private_key_data const& d, crypto_call_context const& call)
	: call_(call)
	, type_(d.ecdsa_type)
	, ecc_point_(d.ecc_point.begin(), d.ecc_point.end())
	, priv_key_(d.privkey.data.begin(), d.privkey.data.end())
	{
		CryptoPP::Integer x;
		x.Decode(to_uint8_ptr(priv_key_), priv_key_.size());
		ecdsa_privkey_.Initialize(CryptoPP::ASN1::secp256r1(), x);
		is_valid_ = ecdsa_privkey_.Validate(random_generator(), 3);
		if(is_valid_) {
			//lets validate the public key
			cryptopp_ecdsa_public_key pubkey;
			is_valid_ = decode_ecc_point(ecdsa_public_key_data{type_, ecc_point_}, pubkey);
		}
	}

	ecdsa_private_key(private_key_info const& info, crypto_call_context const& call)
	: call_(call)
	, type_(info.type)
	{
		ecdsa_privkey_.Initialize(random_generator(), CryptoPP::ASN1::secp256r1());
		is_valid_ = ecdsa_privkey_.Validate(random_generator(), 3);
		if(is_valid_) {
			//lets get the private key data out
			CryptoPP::Integer const& x = ecdsa_privkey_.GetPrivateExponent();
			priv_key_.resize(x.MinEncodedSize());
			x.Encode(to_uint8_ptr(priv_key_), priv_key_.size());

			//lets get the public key
			cryptopp_ecdsa_public_key pkey;
			ecdsa_privkey_.MakePublicKey(pkey);
			is_valid_ = pkey.Validate(random_generator(), 3);
			if(is_valid_) {
				CryptoPP::ECP::Point const& q = pkey.GetPublicElement();
				ecc_point_.resize(65);
				ecc_point_[0] = std::byte{0x04};

				SPSSH_ASSERT(q.x.MinEncodedSize() == 32, "invalid integer");
				SPSSH_ASSERT(q.y.MinEncodedSize() == 32, "invalid integer");

				q.x.Encode(to_uint8_ptr(ecc_point_)+1, 32);
				q.y.Encode(to_uint8_ptr(ecc_point_)+33, 32);
			}
		}
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

		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer sig(ecdsa_privkey_);
		std::size_t size = sig.SignMessage(random_generator(), to_uint8_ptr(in), in.size(), to_uint8_ptr(out));
		if(size < signature_size()) {
			zero_pad(safe_subspan(out, 0, size), signature_size(), out);
		}

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
	CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey ecdsa_privkey_;
};


std::shared_ptr<ssh::private_key> create_private_key(private_key_data const& d, crypto_call_context const& call) {
	try {
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
	} catch(CryptoPP::Exception const& ex) {
		call.log.log(logger::error, "cryptopp exception: {}", ex.what());
	}
	return nullptr;
}

std::shared_ptr<ssh::private_key> generate_private_key(private_key_info const& info, crypto_call_context const& call) {
	try {
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
	} catch(CryptoPP::Exception const& ex) {
		call.log.log(logger::error, "cryptopp exception: {}", ex.what());
	}
	return nullptr;
}

}
