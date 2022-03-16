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

std::string_view to_string(compress_type t) {
	using enum compress_type;
	if(t == none) return "none";
	return "unknown";
}

compress_type compress_type_from_string(std::string_view s) {
	using enum compress_type;
	if(s == "none") return none;
	return unknown;
}

std::string_view to_string(key_type t) {
	using enum key_type;
	if(t == ssh_rsa) return "ssh-rsa";
	if(t == ssh_ed25519) return "ssh-ed25519";
	if(t == ecdsa_sha2_nistp256) return "ecdsa-sha2-nistp256";
	return "unknown";
}

key_type ssh_key_type_from_string(std::string_view s) {
	using enum key_type;
	if(s == "ssh-rsa") return ssh_rsa;
	if(s == "ssh-ed25519") return ssh_ed25519;
	if(s == "ecdsa-sha2-nistp256") return ecdsa_sha2_nistp256;
	return unknown;
}

}
