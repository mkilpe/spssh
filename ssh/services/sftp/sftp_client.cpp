#include "sftp_client.hpp"
#include "sftp.hpp"
#include "packet_ser_impl.hpp"
#include "protocol.hpp"

namespace securepath::ssh::sftp {

sftp_client::sftp_client(transport_base& transport, channel_side_info local, std::size_t buffer_size)
: channel(transport, local, buffer_size)
{
}

bool sftp_client::on_confirm(channel_side_info remote, const_span extra_data) {
	if(channel::on_confirm(remote, extra_data)) {
		send_packet<init>(sftp_version);
	}
	return true;
}

bool sftp_client::on_data(const_span s) {
	return true;
}

}
