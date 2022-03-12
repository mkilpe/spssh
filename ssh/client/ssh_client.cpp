#include "ssh_client.hpp"
#include "ssh/core/protocol_helpers.hpp"

namespace securepath::ssh {

ssh_client::ssh_client(ssh_config const& conf, logger& log, out_buffer& buf)
: ssh_transport(conf, buf, log)
{
}

bool ssh_client::send_initial_packet() {
	bool ret = send_version_string(config_.my_version, output_buffer());
	if(ret) {
		set_state(ssh_state::version_exchange);
	}
	return ret;
}

}
