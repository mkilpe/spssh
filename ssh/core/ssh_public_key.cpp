
#include "ssh_public_key.hpp"

namespace securepath::ssh {

std::string_view to_string(ssh_key_type t) {
	using enum ssh_key_type;
	if(t == ssh_rsa) return "ssh-rsa";
	if(t == ssh_ed25519) return "ssh-ed25519";
	if(t == ecdsa_sha2_nistp256) return "ecdsa-sha2-nistp256";
	return "unknown";
}

ssh_key_type ssh_key_type_from_string(std::string_view s) {
	using enum ssh_key_type;
	if(s == "ssh-rsa") return ssh_rsa;
	if(s == "ssh-ed25519") return ssh_ed25519;
	if(s == "ecdsa-sha2-nistp256") return ecdsa_sha2_nistp256;
	return unknown;
}

}
