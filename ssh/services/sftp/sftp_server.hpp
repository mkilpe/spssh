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

protected:
	std::shared_ptr<sftp_server_backend> backend_;
	byte_vector in_data_;
	std::size_t in_used_{};
};

}

#endif