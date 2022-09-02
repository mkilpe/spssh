#ifndef SP_SSH_SFTP_COMMON_HEADER
#define SP_SSH_SFTP_COMMON_HEADER

#include "packet_types.hpp"
#include "ssh/core/connection/channel.hpp"

namespace securepath::ssh::sftp {

//t: check max packet size

/// common base for client and server, mostly to handle in-data buffering
class sftp_common : public channel {
public:
	sftp_common(transport_base& transport, channel_side_info local, std::size_t buffer_size = default_buffer_size);
	sftp_common(channel&& predecessor);
	~sftp_common();

	bool on_data(const_span) override;

protected:
	virtual void handle_sftp_packet(sftp_packet_type, const_span data) = 0;

	void close(std::string_view error);

protected:
	byte_vector in_data_;
	std::size_t in_used_{};
};

}

#endif