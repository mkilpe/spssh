#ifndef SP_SSH_SFTP_CLIENT_HEADER
#define SP_SSH_SFTP_CLIENT_HEADER

#include "sftp_common.hpp"
#include "sftp_client_interface.hpp"

#include <map>

namespace securepath::ssh::sftp {

class sftp_client : public sftp_common, public sftp_client_interface {
public:
	sftp_client(std::shared_ptr<sftp_client_callback> callback, transport_base& transport, channel_side_info local, std::size_t buffer_size = default_buffer_size);

public: // sftp_client_interface
	void close(std::string_view error) override;
	call_handle open_file(std::string_view path, open_mode mode, file_attributes = {}) override;
	call_handle read_file(file_handle_view, std::uint64_t pos, std::uint32_t size) override;
	call_handle write_file(file_handle_view, std::uint64_t pos, const_span data) override;
	call_handle close_file(file_handle_view) override;

	call_handle open_dir(std::string_view path) override;
	call_handle read_dir(dir_handle_view) override;
	call_handle close_dir(dir_handle_view) override;

protected: // sftp_common
	bool on_confirm(channel_side_info remote, const_span extra_data) override;
	void on_request_success() override;
	void on_request_failure() override;
	void handle_sftp_packet(sftp_packet_type type, const_span data) override;

protected:
	void handle_version(const_span);
	void handle_status(const_span);
	void handle_handle(const_span);
	void handle_data(const_span);
	void handle_name(const_span);
	void handle_attrs(const_span);
	void handle_extended_reply(const_span);

protected:
	template<typename PacketType, sftp_packet_type Type, typename... Args>
	call_handle send_sftp_packet(Args&&... args);

protected:
	// previous packet id
	std::uint32_t sequence_{};
	std::shared_ptr<sftp_client_callback> callback_;

	struct call_data {
		sftp_packet_type type{};
	};

	std::map<call_handle, call_data> remote_calls_;
};

}

#endif