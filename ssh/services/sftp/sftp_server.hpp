#ifndef SP_SSH_SFTP_SERVER_HEADER
#define SP_SSH_SFTP_SERVER_HEADER

#include "ssh/core/connection/channel.hpp"

namespace securepath::ssh::sftp {

class sftp_server : public channel {
public:
	sftp_server(transport_base& transport, channel_side_info local, std::size_t buffer_size = default_buffer_size);
};

}

#endif