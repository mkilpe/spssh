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

	virtual call_handle open_file(std::string_view path, open_mode mode, file_attributes const& = {}) = 0;
	virtual call_handle read_file(file_handle_view, std::uint64_t pos, std::uint32_t size) = 0;
	virtual call_handle write_file(file_handle_view, std::uint64_t pos, const_span data) = 0;
	virtual call_handle close_file(file_handle_view) = 0;
	virtual call_handle stat_file(file_handle_view) = 0;
	virtual call_handle setstat_file(file_handle_view, file_attributes const&) = 0;

	virtual call_handle open_dir(std::string_view path) = 0;
	virtual call_handle read_dir(dir_handle_view) = 0;
	virtual call_handle close_dir(dir_handle_view) = 0;

	virtual call_handle remove_file(std::string_view path) = 0;
	virtual call_handle rename(std::string_view old_path, std::string_view new_path) = 0;
	virtual call_handle mkdir(std::string_view path, file_attributes const& = {}) = 0;
	virtual call_handle remove_dir(std::string_view path) = 0;

	virtual call_handle stat(std::string_view path, bool follow_symlinks = true) = 0;
	virtual call_handle setstat(std::string_view path, file_attributes const&) = 0;

	virtual call_handle readlink(std::string_view path) = 0;
	virtual call_handle symlink(std::string_view link, std::string_view path) = 0;

	virtual call_handle realpath(std::string_view path) = 0;

	virtual call_handle extended(std::string_view ext_request, const_span data) = 0;

protected:
	~sftp_client_interface() = default;
};

class open_file_data;
class read_file_data;
class write_file_data;
class close_file_data;
class state_file_data;
class setstate_file_data;
class open_dir_data;
class read_dir_data;
class close_dir_data;
class remove_file_data;
class rename_data;
class mkdir_data;
class remove_dir_data;
class stat_data;
class setstat_data;
class readlink_data;
class symlink_data;
class realpath_data;
class extended_data;

class sftp_client_callback {
public:
	virtual ~sftp_client_callback() = default;

	/// fxp_version packet received, return false if the connection should not be accepted.
	virtual bool on_version(std::uint32_t version, ext_data_view data) = 0;

	/// called if any of the commands after agreeing on version fails
	virtual void on_failure(call_handle, sftp_error) = 0;

	virtual void on_open_file(call_handle, open_file_data result) = 0;
	virtual void on_read_file(call_handle, read_file_data result) = 0;
	virtual void on_write_file(call_handle, write_file_data result) = 0;
	virtual void on_close_file(call_handle, close_file_data result) = 0;
	virtual void on_stat_file(call_handle, state_file_data result) = 0;
	virtual void on_setstat_file(call_handle, setstate_file_data result) = 0;

	virtual void on_open_dir(call_handle, open_dir_data result) = 0;
	virtual void on_read_dir(call_handle, read_dir_data result) = 0;
	virtual void on_close_dir(call_handle, close_dir_data result) = 0;

	virtual void on_remove_file(call_handle, remove_file_data result) = 0;
	virtual void on_rename(call_handle, rename_data result) = 0;
	virtual void on_mkdir(call_handle, mkdir_data result) = 0;
	virtual void on_remove_dir(call_handle, remove_dir_data result) = 0;

	virtual void on_stat(call_handle, stat_data result) = 0;
	virtual void on_setstat(call_handle, setstat_data result) = 0;

	virtual void on_readlink(call_handle, readlink_data result) = 0;
	virtual void on_symlink(call_handle, symlink_data result) = 0;

	virtual void on_realpath(call_handle, realpath_data result) = 0;
	virtual void on_extended(call_handle, extended_data result) = 0;
};

struct open_file_data {
	file_handle handle;
};

struct read_file_data {
	const_span data;
};

struct write_file_data {
};

struct close_file_data {
};

struct state_file_data {
	file_attributes attrs;
};

struct setstate_file_data {
};


struct open_dir_data {
	dir_handle handle;
};

struct file_info {
	std::string_view filename;
	std::string_view longname;
	file_attributes attrs;
};

struct read_dir_data {
	std::vector<file_info> files;
};

struct close_dir_data {
};

struct remove_file_data {
};

struct rename_data {
};

struct mkdir_data {
};

struct remove_dir_data {
};

struct stat_data {
	file_attributes attrs;
};

struct setstat_data {
};

struct readlink_data {
	std::string_view path;
};

struct symlink_data {
};

struct realpath_data {
	std::string_view path;
};

struct extended_data {
	const_span data;
};

}

#endif