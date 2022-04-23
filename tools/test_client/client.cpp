
#include "client.hpp"
#include "ssh/core/kex.hpp"

namespace securepath::ssh {

handler_result ssh_test_client::handle_kex_done(kex const& k) {
	auto key = k.server_host_key();
	logger_.log(logger::info, "Server host key ({}) fingerprint: {}", to_string(key.type()), key.fingerprint(crypto(), call_context()));
	//check the above key is trusted, if not set_error_and_disconnect(ssh_key_exchange_failed);
	return ssh_client::handle_kex_done(k);
}

}
