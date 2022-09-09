#ifndef SP_SSH_SFTP_CLIENT_INTERFACE_HEADER
#define SP_SSH_SFTP_CLIENT_INTERFACE_HEADER

#include "file_attributes.hpp"
#include "sftp.hpp"
#include "ssh/common/logger.hpp"

namespace securepath::ssh::sftp {

class sftp_client_interface {
public:
	/// close the channel and set error if given
	virtual void close(std::string_view error = {}) = 0;

	virtual call_handle open_file(std::string_view path, open_mode mode, file_attributes = {}) = 0;
	virtual call_handle read_file(file_handle_view, std::uint64_t pos, std::uint32_t size) = 0;
	virtual call_handle write_file(file_handle_view, std::uint64_t pos, const_span data) = 0;
	virtual call_handle close_file(file_handle_view) = 0;

	virtual call_handle open_dir(std::string_view path) = 0;
	virtual call_handle read_dir(dir_handle_view) = 0;
	virtual call_handle close_dir(dir_handle_view) = 0;

protected:
	~sftp_client_interface() = default;
};

class open_file_data;
class read_file_data;
class write_file_data;
class close_file_data;
class open_dir_data;
class read_dir_data;
class close_dir_data;

class sftp_client_callback {
public:
	virtual ~sftp_client_callback() = default;

	/// fxp_version packet received, return false if cannot accept the version.
	virtual bool on_version(std::uint32_t version, ext_data_view data) = 0;

	virtual void on_open_file(sftp_result<open_file_data> result) = 0;
	virtual void on_read_file(sftp_result<read_file_data> result) = 0;
	virtual void on_write_file(sftp_result<write_file_data> result) = 0;
	virtual void on_close_file(sftp_result<close_file_data> result) = 0;

	virtual void on_open_dir(sftp_result<open_file_data> result) = 0;
	virtual void on_read_dir(sftp_result<read_dir_data> result) = 0;
	virtual void on_close_dir(sftp_result<close_dir_data> result) = 0;
};

struct open_file_data {
	file_handle handle;
};

struct read_file_data {
	const_span data;
};

struct write_file_data {};
struct close_file_data {};

struct open_dir_data {
	dir_handle handle;
};

struct read_dir_data {
	std::vector<std::string_view> files;
};

struct close_dir_data {};

}

#endif