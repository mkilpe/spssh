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
	template<typename PacketType, std::uint16_t Type, typename... Args>
	call_handle send_sftp_packet(Args&&... args);

	void call_status_result(call_handle id, sftp_error err);
	void call_handle_result(call_handle id, std::string_view handle);
	void call_data_result(call_handle id, std::string_view data);
	void call_name_result(call_handle id, std::vector<file_info> files);
	void call_attr_result(call_handle id, file_attributes attrs);

	virtual void on_extended_reply(call_handle id, ssh_bf_reader&);

protected:
	// previous packet id
	std::uint32_t sequence_{};
	std::shared_ptr<sftp_client_callback> callback_;

	struct call_data {
		std::uint16_t type{};
	};

	std::map<call_handle, call_data> remote_calls_;
};

}

#endif