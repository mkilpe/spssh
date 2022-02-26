#include "ssh_server.hpp"

namespace securepath::ssh {

ssh_server::ssh_server(ssh_config const& conf, logger& log, out_buffer& buf)
: ssh_transport(conf, buf, log)
{
}


}
