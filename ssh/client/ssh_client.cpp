#include "ssh_client.hpp"
#include "ssh/core/protocol_helpers.hpp"

namespace securepath::ssh {

ssh_client::ssh_client(ssh_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: ssh_transport(conf, log, out, std::move(cc))
{
}

}
