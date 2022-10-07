#ifndef SP_SSH_SFTP_SERVER_BACKEND_HEADER
#define SP_SSH_SFTP_SERVER_BACKEND_HEADER

#include "file_attributes.hpp"
#include "sftp.hpp"
#include "ssh/common/logger.hpp"

namespace securepath::ssh::sftp {

using call_context = std::uint64_t;

/// Interface to callback for server backend (the interface is separated to allow async handling of the server backend)
class sftp_server_interface {
public:
	/// close the channel and set error if given
	virtual void close(std::string_view error = {}) = 0;

	/// send an error, can be a response to any command that has call context
	virtual bool send_error(call_context, status_code code, std::string_view message);

	/// send operation succeeded, this can be used with all commands that do not return any data
	virtual bool send_ok(call_context);

	/// send fxp_version packet
	virtual bool send_version(std::uint32_t version, ext_data_view = {}) = 0;

	/// send response to open file with file handle
	virtual bool send_open_file(call_context, file_handle_view) = 0;

	/// send response to open_dir
	virtual bool send_open_dir(call_context, dir_handle_view) = 0;

	/// send response to stat and stat_file
	virtual bool send_stat(call_context, file_attributes) = 0;

	/// send response to readlink and realpath
	virtual bool send_path(call_context, std::string_view path) = 0;

	/// send response to extended
	virtual bool send_extended(call_context, const_span data) = 0;

protected:
	~sftp_server_interface() = default;
};

/// Interface for the server commands
class sftp_server_backend {
public:
	sftp_server_backend(logger&);
	virtual ~sftp_server_backend() = default;

	/// called when sftp channel is created, the parameter should be saved for later use
	virtual void attach(sftp_server_interface*);

	/// called when sftp channel is closed, the parameter for attach must not be used after this
	virtual void detach();

	/// fxp_init packet received, should set error or response with send_version
	virtual void on_init(std::uint32_t version, ext_data_view data);

	virtual void on_open_file(call_context, std::string_view path, open_mode mode, file_attributes attrs) = 0;
	virtual void on_close_file(call_context, file_handle_view) = 0;
	virtual void on_read_file(call_context, file_handle_view, std::uint64_t pos, std::uint32_t size) = 0;
	virtual void on_write_file(call_context, file_handle_view, std::uint64_t pos, const_span data) = 0;

	virtual void on_stat_file(call_context, file_handle_view) = 0;
	virtual void on_setstat_file(call_context, file_handle_view, file_attributes) = 0;

	virtual void on_open_dir(call_context, std::string_view path) = 0;
	virtual void on_read_dir(call_context, dir_handle_view) = 0;
	virtual void on_close_dir(call_context, dir_handle_view) = 0;

	virtual void on_remove_file(call_context, std::string_view path) = 0;
	virtual void on_rename(call_context, std::string_view old_path, std::string_view new_path) = 0;
	virtual void on_mkdir(call_context, std::string_view path, file_attributes) = 0;
	virtual void on_remove_dir(call_context, std::string_view path) = 0;

	virtual void on_stat(call_context, std::string_view path, bool follow_symlinks) = 0;
	virtual void on_setstat(call_context, std::string_view path, file_attributes) = 0;

	virtual void on_readlink(call_context, std::string_view path) = 0;
	virtual void on_symlink(call_context, std::string_view link, std::string_view path) = 0;

	virtual void on_realpath(call_context, std::string_view path) = 0;

	virtual void on_extended(call_context, std::string_view ext_request, const_span data) = 0;
protected:
	logger& log_;
	sftp_server_interface* s_{};
};

}

#endif