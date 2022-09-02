#ifndef SP_SSH_SFTP_CLIENT_HEADER
#define SP_SSH_SFTP_CLIENT_HEADER

#include "sftp_common.hpp"
#include "sftp_client_interface.hpp"

namespace securepath::ssh::sftp {

class sftp_client : public sftp_common, public sftp_client_interface {
public:
	sftp_client(std::shared_ptr<sftp_client_callback> callback, transport_base& transport, channel_side_info local, std::size_t buffer_size = default_buffer_size);

public:
	void close(std::string_view error) override;
	call_handle open_file(std::string_view path, open_mode mode, file_attributes = {}) override;
	call_handle read_file(file_handle_view, std::uint64_t pos, std::uint32_t size) override;
	call_handle write_file(file_handle_view, std::uint64_t pos, const_span data) override;
	call_handle close_file(file_handle_view) override;

protected:
	bool on_confirm(channel_side_info remote, const_span extra_data) override;
	void handle_sftp_packet(sftp_packet_type type, const_span data) override;
	void handle_version(const_span s);

protected:
	// previous packet id
	std::uint32_t sequence_{};
	std::shared_ptr<sftp_client_callback> callback_;
};

}

#endif