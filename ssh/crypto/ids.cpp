#include "ids.hpp"

namespace securepath::ssh {

std::string_view to_string(cipher_type t) {
	using enum cipher_type;
	if(t == aes_256_gcm) return "AEAD_AES_256_GCM";
	if(t == aes_256_ctr) return "aes256-ctr";
	return "unknown";
}

cipher_type from_string(type_tag<cipher_type>, std::string_view s) {
	using enum cipher_type;
	if(s == "AEAD_AES_256_GCM") return aes_256_gcm;
	if(s == "aes256-ctr") return aes_256_ctr;
	return unknown;
}

std::size_t cipher_iv_size(cipher_type t) {
	using enum cipher_type;
	if(t == aes_256_gcm) return 12;
	if(t == aes_256_ctr) return 16;
	return 0;
}

std::size_t cipher_key_size(cipher_type t) {
	using enum cipher_type;
	if(t == aes_256_gcm) return 32;
	if(t == aes_256_ctr) return 32;
	return 0;
}

std::string_view to_string(mac_type t) {
	using enum mac_type;
	if(t == aes_256_gcm) return "AEAD_AES_256_GCM";
	if(t == hmac_sha2_256) return "hmac-sha2-256";
	return "unknown";
}

mac_type from_string(type_tag<mac_type>, std::string_view s) {
	using enum mac_type;
	if(s == "AEAD_AES_256_GCM") return aes_256_gcm;
	if(s == "hmac-sha2-256") return hmac_sha2_256;
	return unknown;
}

std::size_t mac_key_size(mac_type t) {
	using enum mac_type;
	if(t == aes_256_gcm) return 0;
	if(t == hmac_sha2_256) return 32;
	return 0;
}

std::string_view to_string(compress_type t) {
	using enum compress_type;
	if(t == none) return "none";
	return "unknown";
}

compress_type from_string(type_tag<compress_type>, std::string_view s) {
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

std::string_view to_curve_name(key_type t) {
	using enum key_type;
	if(t == ecdsa_sha2_nistp256) return "nistp256";
	return "";
}

key_type from_string(type_tag<key_type>, std::string_view s) {
	using enum key_type;
	if(s == "ssh-rsa") return ssh_rsa;
	if(s == "ssh-ed25519") return ssh_ed25519;
	if(s == "ecdsa-sha2-nistp256") return ecdsa_sha2_nistp256;
	return unknown;
}

std::string_view to_string(key_exchange_type t) {
	using enum key_exchange_type;
	if(t == X25519) return "X25519";
	return "unknown";
}

key_exchange_type from_string(type_tag<key_exchange_type>, std::string_view s) {
	using enum key_exchange_type;
	if(s == "X25519") return X25519;
	return unknown;
}

std::string_view to_string(hash_type t) {
	using enum hash_type;
	if(t == sha2_256) return "sha2-256";
	if(t == sha2_512) return "sha2-512";
	return "unknown";
}

hash_type from_string(type_tag<hash_type>, std::string_view s) {
	using enum hash_type;
	if(s == "sha2-256") return sha2_256;
	if(s == "sha2-512") return sha2_512;
	return unknown;
}

}
