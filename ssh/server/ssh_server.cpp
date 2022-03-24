#include "ssh_server.hpp"

namespace securepath::ssh {

ssh_server::ssh_server(ssh_config const& conf, logger& log, out_buffer& out, crypto_context cc)
: ssh_transport(conf, log, out, std::move(cc))
{
}


}
