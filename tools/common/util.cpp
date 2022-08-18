#include "util.hpp"

#include <fstream>

namespace securepath::ssh {

byte_vector read_file(std::string const& file) {
	byte_vector b;
	std::ifstream f(file, std::ios_base::binary);
	if(f) {
		f.seekg(0, std::ios_base::end);
		auto size = f.tellg();
		f.seekg(0, std::ios_base::beg);
		b.resize(size);
		f.read((char*)b.data(), size);
	}
	return b;
}

ssh_config test_tool_default_config() {
	ssh_config c;

	c.algorithms.host_keys = {key_type::ssh_ed25519, key_type::ssh_rsa, key_type::ecdsa_sha2_nistp256};
	c.algorithms.kexes = {kex_type::curve25519_sha256, kex_type::libssh_curve25519_sha256, kex_type::dh_group16_sha512, kex_type::dh_group14_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm, cipher_type::aes_256_ctr};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm, cipher_type::aes_256_ctr};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm, mac_type::hmac_sha2_256};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm, mac_type::hmac_sha2_256};

	c.random_packet_padding = false;

	return c;
}

}