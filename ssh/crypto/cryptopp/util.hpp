#ifndef SP_SSH_CRYPTO_CRYPTOPP_UTIL_HEADER
#define SP_SSH_CRYPTO_CRYPTOPP_UTIL_HEADER

#include "random.hpp"
#include "ssh/common/types.hpp"
#include "ssh/crypto/public_key.hpp"

#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>

namespace securepath::ssh::cryptopp {

using cryptopp_ecdsa_public_key = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey;

inline bool decode_ecc_point(ecdsa_public_key_data const& d, cryptopp_ecdsa_public_key& pubkey) {
	bool valid = false;
	// see the size is correct and it is uncompressed ecc point, otherwise don't bother
	if(d.ecc_point.size() == 65 && d.ecc_point[0] == std::byte{0x04}) {
		CryptoPP::ECP::Point q;
		q.identity = false;
		q.x.Decode(to_uint8_ptr(d.ecc_point)+1, 32);
		q.y.Decode(to_uint8_ptr(d.ecc_point)+33, 32);

		//for now we only support this type of curve
		pubkey.Initialize(CryptoPP::ASN1::secp256r1(), q);
		valid = pubkey.Validate(random_generator(), 3);
	}
	return valid;
}

}

#endif
