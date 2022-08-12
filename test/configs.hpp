
#ifndef SP_SSH_TEST_CONFIGS_HEADER
#define SP_SSH_TEST_CONFIGS_HEADER

#include "crypto.hpp"

#include "ssh/client/client_config.hpp"
#include "ssh/server/server_config.hpp"

namespace securepath::ssh::test {

// simple encryption contexts for client and server to connect

client_config test_client_config();
server_config test_server_config();

client_config test_client_aes_ctr_config();
server_config test_server_aes_ctr_config();

client_config test_client_dh_kex_config();
server_config test_server_dh_kex_config();

}

#endif
