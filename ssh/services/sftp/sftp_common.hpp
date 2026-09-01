#ifndef SP_SSH_SFTP_COMMON_HEADER
#define SP_SSH_SFTP_COMMON_HEADER

#include "packet_types.hpp"
#include "sftp.hpp"
#include "ssh/core/connection/channel.hpp"
#include "ssh/core/ssh_binary_util.hpp"

#include <vector>

namespace securepath::ssh::sftp {

/// default size for the buffer used to combine incoming data into sftp packets (must fit the biggest accepted packet)
std::size_t const default_sftp_in_buffer_size{1024*256};

/// read extension name/data pairs until the end of the given reader view
bool read_extension_data(ssh_bf_reader&, std::vector<ext_data_view>& out);

/// common base for client and server, mostly to handle in-data buffering
class sftp_common : public channel {
public:
	sftp_common(transport_base& transport, channel_side_info local
		, std::size_t buffer_size = default_buffer_size
		, std::size_t in_buffer_size = default_sftp_in_buffer_size);
	sftp_common(channel&& predecessor, std::size_t in_buffer_size = default_sftp_in_buffer_size);
	~sftp_common();

	bool on_data(const_span) override;

protected:
	virtual void handle_sftp_packet(sftp_packet_type, const_span data) = 0;

	void close(std::string_view error);

private:
	bool is_valid_packet_length(std::uint32_t length) const;

protected:
	byte_vector in_data_;
	std::size_t in_used_{};
};

}

#endif
