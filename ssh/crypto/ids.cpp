#include "ids.hpp"

namespace securepath::ssh {

std::string_view to_string(cipher_type t) {
	using enum cipher_type;
	if(t == aes_256_gcm) return "AEAD_AES_256_GCM";
	if(t == aes_256_ctr) return "aes256-ctr";
	return "unknown";
}

cipher_type cipher_type_from_string(std::string_view s) {
	using enum cipher_type;
	if(s == "AEAD_AES_256_GCM") return aes_256_gcm;
	if(s == "aes256-ctr") return aes_256_ctr;
	return unknown;
}

std::string_view to_string(mac_type t) {
	using enum mac_type;
	if(t == aes_256_gcm) return "AEAD_AES_256_GCM";
	if(t == hmac_sha2_256) return "hmac-sha2-256";
	return "unknown";
}

mac_type mac_type_from_string(std::string_view s) {
	using enum mac_type;
	if(s == "AEAD_AES_256_GCM") return aes_256_gcm;
	if(s == "hmac-sha2-256") return hmac_sha2_256;
	return unknown;
}

}
