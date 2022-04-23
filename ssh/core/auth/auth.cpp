#include "auth.hpp"

namespace securepath::ssh {

std::string_view to_string(auth_type t) {
	using enum auth_type;
	if(t == none) return "none";
	if(t == public_key) return "publickey";
	if(t == password) return "password";
	if(t == hostbased) return "hostbased";
	if(t == interactive) return "keyboard-interactive";
	return "unknown";
}

auth_bits operator|(auth_type l, auth_type r) {
	return auth_bits(l) | auth_bits(r);
}

auth_bits operator&(auth_bits l, auth_type r) {
	return l & auth_bits(r);
}

}
