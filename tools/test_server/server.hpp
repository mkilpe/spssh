#ifndef SP_SSH_TOOLS_TEST_SERVER_SERVER_HEADER
#define SP_SSH_TOOLS_TEST_SERVER_SERVER_HEADER

#include "ssh/server/ssh_server.hpp"

namespace securepath::ssh {

class ssh_test_server : public ssh_server {
public:
	ssh_test_server(ssh_config const&, logger& log, out_buffer&, crypto_context&);

protected:
	std::unique_ptr<ssh_service> construct_service(std::string_view name) override;
//	handler_result handle_kex_done(kex const&) override;
};

}

#endif