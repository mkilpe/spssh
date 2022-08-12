#include "kex.hpp"
#include "kex/curve25519_sha256_kex.hpp"
#include "kex/diffie_hellman_kex.hpp"

namespace securepath::ssh {

std::unique_ptr<kex> construct_kex(transport_side side, kex_type t, kex_context kex_c) {
	using enum kex_type;
	if(t == curve25519_sha256) {
		if(side == transport_side::client) {
			return std::make_unique<curve25519_sha256_kex_client>(kex_c);
		} else {
			return std::make_unique<curve25519_sha256_kex_server>(kex_c);
		}
	} else if(t == dh_group14_sha256 || t == dh_group16_sha512) {
		if(side == transport_side::client) {
			return std::make_unique<diffie_hellman_kex_client>(kex_c, t);
		} else {
			return std::make_unique<diffie_hellman_kex_server>(kex_c, t);
		}

	}
	return nullptr;
}

}

