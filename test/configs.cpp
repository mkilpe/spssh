
#include "configs.hpp"

namespace securepath::ssh::test {

client_config test_client_config() {
	client_config c;
	c.side = transport_side::client;
	c.algorithms.host_keys = {key_type::ssh_ed25519};
	c.algorithms.kexes = {kex_type::curve25519_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm};

	//c.random_packet_padding = false;

	return c;
}

server_config test_server_config() {
	server_config c;
	c.side = transport_side::server;
	c.algorithms.host_keys = {key_type::ssh_ed25519};
	c.algorithms.kexes = {kex_type::curve25519_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm};

	crypto_test_context crypto;

	std::vector<ssh_private_key> keys;
	keys.push_back(crypto.test_ed25519_private_key());
	c.set_host_keys_for_server(std::move(keys));

	return c;
}

}
