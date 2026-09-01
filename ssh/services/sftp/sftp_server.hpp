#ifndef SP_SSH_SFTP_SERVER_HEADER
#define SP_SSH_SFTP_SERVER_HEADER

#include "sftp_common.hpp"
#include "sftp_server_backend.hpp"

#include <set>

namespace securepath::ssh::sftp {

class sftp_server : public sftp_common, public sftp_server_interface {
public:
	sftp_server(channel&& predecessor, std::shared_ptr<sftp_server_backend>);
	~sftp_server();

	void on_state_change() override;

public: //sftp_server_interface
	void close(std::string_view error) override;
	bool send_version(std::uint32_t version, std::vector<ext_data_view> const& data) override;
	bool send_error(call_context, status_code code, std::string_view message) override;
	bool send_ok(call_context) override;
	bool send_open_file(call_context, file_handle_view) override;
	bool send_open_dir(call_context, dir_handle_view) override;
	bool send_read_dir(call_context, std::vector<file_info> const&) override;
	bool send_stat(call_context, file_attributes const&) override;
	bool send_path(call_context, std::string_view path) override;
	bool send_extended(call_context, const_span data) override;

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
	void send_unsupported(sftp_packet_type, const_span data);
private:
	template<typename Packet, typename Func>
	void handle_packet_helper(Func, const_span);

protected:
	std::shared_ptr<sftp_server_backend> backend_;
	// handles given out for open directories, so that fxp_close can be routed correctly
	std::set<std::string, std::less<>> dir_handles_;
};

}

#endif
