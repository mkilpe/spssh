#include "kexinit.hpp"
#include "ssh_config.hpp"
#include "supported_algorithms.hpp"
#include "ssh/common/logger.hpp"

#include <ostream>

namespace securepath::ssh {

std::string_view to_string(kex_type t) {
	using enum kex_type;
	if(t == dh_group14_sha256) return "diffie-hellman-group14-sha256";
	if(t == curve25519_sha256) return "curve25519-sha256";
	if(t == ecdh_sha2_nistp256) return "ecdh-sha2-nistp256";
	return "unknown";
}

kex_type from_string(type_tag<kex_type>, std::string_view s) {
	using enum kex_type;
	if(s == "diffie-hellman-group14-sha256") return dh_group14_sha256;
	if(s == "curve25519-sha256") return curve25519_sha256;
	if(s == "ecdh-sha2-nistp256") return ecdh_sha2_nistp256;
	return unknown;
}

std::ostream& operator<<(std::ostream& out, crypto_configuration const& c) {
	return out << "kex=" << to_string(c.kex) << " host_key=" << to_string(c.host_key)
		<< " in={cipher=" << to_string(c.in.cipher) << " mac=" << to_string(c.in.mac) << " compress=" << to_string(c.in.compress)
		<< "} out={cipher=" << to_string(c.out.cipher) << " mac=" << to_string(c.out.mac) << " compress=" << to_string(c.out.compress)
		<< "}";
}

bool crypto_configuration::valid() const {
	return kex != kex_type::unknown && host_key != key_type::unknown &&
		in.cipher != cipher_type::unknown && in.mac != mac_type::unknown && in.compress != compress_type::unknown &&
		out.cipher != cipher_type::unknown && out.mac != mac_type::unknown && out.compress != compress_type::unknown;
}

static bool is_compatible(kex_type kex, key_type key) {
	using enum kex_type;
	if(kex == curve25519_sha256) {
		return key_capabilities[std::size_t(key)] & signature_capable;
	}
	if(kex == dh_group14_sha256) {
		return key_capabilities[std::size_t(key)] & signature_capable;
	}
	if(kex == ecdh_sha2_nistp256) {
		return key_capabilities[std::size_t(key)] & signature_capable;
	}

	return false;
}

static bool is_supported_kex(kex_type client_kex, supported_algorithms const& client, supported_algorithms const& server, key_type& ktype) {
	if(server.kexes.supports(client_kex)) {
		// do we have compatible host key
		for(auto&& client_hkey : client.host_keys) {
			if(is_compatible(client_kex, client_hkey)) {
				// does the server support it too?
				if(server.host_keys.supports(client_hkey)) {
					ktype = client_hkey;
					return true;
				}
			}
		}
	}

	return false;
}

template<typename IdType>
static bool find_suitable(algo_list<IdType> const& client, algo_list<IdType> const& server, IdType& res) {
	for(auto&& v : client) {
		if(server.supports(v)) {
			res = v;
			return true;
		}
	}
	return false;
}

kexinit_agreement::kexinit_agreement(logger& logger, transport_side my_side, supported_algorithms const& my)
: logger_(logger)
, my_side_(my_side)
, my_(my)
{}

bool kexinit_agreement::agree(supported_algorithms const& remote) {
	supported_algorithms const& client = my_side_ == transport_side::client ? my_ : remote;
	supported_algorithms const& server = my_side_ == transport_side::client ? remote : my_;

	crypto_configuration res;

	// first find suitable kex and host key algorithms
	for(auto&& ckex : client.kexes) {
		if(is_supported_kex(ckex, client, server, res.host_key)) {
			res.kex = ckex;
			break;
		}
	}

	if(res.kex == kex_type::unknown || res.host_key == key_type::unknown) {
		logger_.log(logger::debug, "SSH failed to find common kex/host_key algorithm");
		return false;
	}

	// find suitable ciphers
	if(!find_suitable(client.client_server_ciphers, server.client_server_ciphers, res.out.cipher)) {
		logger_.log(logger::debug, "SSH failed to find common cipher algorithm");
		return false;
	}
	if(!find_suitable(client.server_client_ciphers, server.server_client_ciphers, res.in.cipher)) {
		logger_.log(logger::debug, "SSH failed to find common cipher algorithm");
		return false;
	}

	// find suitable macs
	if(!find_suitable(client.client_server_macs, server.client_server_macs, res.out.mac)) {
		logger_.log(logger::debug, "SSH failed to find common mac algorithm");
		return false;
	}
	if(!find_suitable(client.server_client_macs, server.server_client_macs, res.in.mac)) {
		logger_.log(logger::debug, "SSH failed to find common mac algorithm");
		return false;
	}

	// sanity check for gcm
	if(res.in.cipher == cipher_type::aes_256_gcm && res.in.mac != mac_type::aes_256_gcm) {
		logger_.log(logger::debug, "SSH aes_256_gcm cipher but not matching mac type");
		return false;
	}
	if(res.out.cipher == cipher_type::aes_256_gcm && res.out.mac != mac_type::aes_256_gcm) {
		logger_.log(logger::debug, "SSH aes_256_gcm cipher but not matching mac type");
		return false;
	}

	// find suitable compression
	if(!find_suitable(client.client_server_compress, server.client_server_compress, res.out.compress)) {
		logger_.log(logger::debug, "SSH failed to find common mac algorithm");
		return false;
	}
	if(!find_suitable(client.server_client_compress, server.server_client_compress, res.in.compress)) {
		logger_.log(logger::debug, "SSH failed to find common mac algorithm");
		return false;
	}

	// if we are server, swap the values
	if(my_side_ == transport_side::server) {
		std::swap(res.in.cipher, res.out.cipher);
		std::swap(res.in.mac, res.out.mac);
		std::swap(res.in.compress, res.out.compress);
	}

	guess_was_correct_ = client.kexes.preferred() == res.kex && server.kexes.preferred() == res.kex;
	agreed_ = res;
	return true;
}

bool kexinit_agreement::was_guess_correct() const {
	return guess_was_correct_;
}

crypto_configuration kexinit_agreement::agreed_configuration() const {
	SPSSH_ASSERT(agreed_, "invalid state");
	return *agreed_;
}

}
