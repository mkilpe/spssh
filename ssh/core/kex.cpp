#include "kex.hpp"

namespace securepath::ssh {

std::string_view to_string(kex_type t) {
	using enum kex_type;
	if(t == dh_group14_sha256) return "diffie-hellman-group14-sha256";
	if(t == curve25519_sha256) return "curve25519-sha256";
	if(t == ecdh_sha2_nistp256) return "ecdh-sha2-nistp256";
	return "unknown";
}

kex_type kex_type_from_string(std::string_view s) {
	using enum kex_type;
	if(s == "diffie-hellman-group14-sha256") return dh_group14_sha256;
	if(s == "curve25519-sha256") return curve25519_sha256;
	if(s == "ecdh-sha2-nistp256") return ecdh_sha2_nistp256;
	return unknown;
}

}
