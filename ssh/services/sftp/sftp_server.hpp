#ifndef SP_SSH_SFTP_SERVER_HEADER
#define SP_SSH_SFTP_SERVER_HEADER

#include "sftp_common.hpp"
#include "sftp_server_backend.hpp"

namespace securepath::ssh::sftp {

//t: check max packet size

class sftp_server : public sftp_common, public sftp_server_interface {
public:
	//sftp_server(std::shared_ptr<sftp_server_backend>, transport_base& transport, channel_side_info local, std::size_t buffer_size = default_buffer_size);
	sftp_server(channel&& predecessor, std::shared_ptr<sftp_server_backend>);
	~sftp_server();

	bool on_data(const_span) override;
	void on_state_change() override;

public: //sftp_server_interface
	void close(std::string_view error) override;
	bool send_version(std::uint32_t version, ext_data_view data) override;

protected:
	void handle_sftp_packet(sftp_packet_type, const_span data) override;
	void handle_init(const_span);
	void handle_open(const_span);
	void handle_close(const_span);
	void handle_read(const_span);
	void handle_write(const_span);
	void handle_lstat(const_span);
	void handle_fstat(const_span);
	void handle_setstat(const_span);
	void handle_fsetstat(const_span);
	void handle_opendir(const_span);
	void handle_readdir(const_span);
	void handle_remove(const_span);
	void handle_mkdir(const_span);
	void handle_rmdir(const_span);
	void handle_realpath(const_span);
	void handle_stat(const_span);
	void handle_rename(const_span);
	void handle_readlink(const_span);
	void handle_symlink(const_span);
	void handle_extended(const_span);

protected:
	std::shared_ptr<sftp_server_backend> backend_;
	byte_vector in_data_;
	std::size_t in_used_{};
};

}

#endif