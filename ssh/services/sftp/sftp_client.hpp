#ifndef SP_SSH_SFTP_CLIENT_HEADER
#define SP_SSH_SFTP_CLIENT_HEADER

#include "ssh/core/connection/channel.hpp"

namespace securepath::ssh::sftp {

class sftp_client : public channel {
public:
	sftp_client(transport_base& transport, channel_side_info local, std::size_t buffer_size = default_buffer_size);


public:
	bool on_confirm(channel_side_info remote, const_span extra_data) override;
	bool on_data(const_span) override;

protected:
	// previous packet id
	std::uint32_t sequence_{};
};

}

#endif