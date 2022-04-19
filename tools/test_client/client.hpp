#ifndef SP_SSH_TOOLS_TEST_CLIENT_CLIENT_HEADER
#define SP_SSH_TOOLS_TEST_CLIENT_CLIENT_HEADER

#include "ssh/client/ssh_client.hpp"

namespace securepath::ssh {

client_config test_client_config();

class ssh_test_client : public ssh_client {
public:
	using ssh_client::ssh_client;

protected:
	handler_result handle_kex_done(kex const&) override;
};

}

#endif