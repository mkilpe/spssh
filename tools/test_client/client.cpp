
#include "client.hpp"
#include "ssh/core/kex.hpp"

namespace securepath::ssh {

client_config test_client_config() {
	client_config c;
	c.side = transport_side::client;
	c.my_version.software = "spssh_test_client";
	c.algorithms.host_keys = {key_type::ssh_ed25519};
	c.algorithms.kexes = {kex_type::curve25519_sha256};
	c.algorithms.client_server_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm};
	c.algorithms.server_client_ciphers = {cipher_type::aes_256_gcm, cipher_type::openssh_aes_256_gcm};
	c.algorithms.client_server_macs = {mac_type::aes_256_gcm};
	c.algorithms.server_client_macs = {mac_type::aes_256_gcm};

	c.random_packet_padding = false;

	c.username = "test";
	c.password = "volatile";

	return c;
}

handler_result ssh_test_client::handle_kex_done(kex const& k) {
	auto key = k.server_host_key();
	logger_.log(logger::info, "Server host key ({}) fingerprint: {}", to_string(key.type()), key.fingerprint(crypto(), call_context()));
	//check the above key is trusted, if not set_error_and_disconnect(ssh_key_exchange_failed);
	return ssh_client::handle_kex_done(k);
}

}
