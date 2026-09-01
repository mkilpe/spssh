#ifndef SP_SSH_SFTP_LOCAL_FS_BACKEND_HEADER
#define SP_SSH_SFTP_LOCAL_FS_BACKEND_HEADER

#include "sftp_server_backend.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <optional>

namespace securepath::ssh::sftp {

/// result of resolving a client given path against the served root directory
struct resolved_path {
	/// the actual filesystem path
	std::filesystem::path full;
	/// normalised path relative to the root
	std::filesystem::path rel;
};

/// Resolve a client path inside root, refusing paths that would escape the root (also through symlinks).
/// Note that this is not race free against concurrent modifications of the served directory tree.
std::optional<resolved_path> confine_path(std::filesystem::path const& root, std::string_view client_path);

/// map the given error code to the closest sftp status code
status_code to_status_code(std::error_code const& ec);

/// turn a root relative path back to the client visible form (always starts with '/')
std::string to_virtual_path(std::filesystem::path const& rel);

/// maximum amount of bytes returned for a single read request
std::uint32_t const max_read_size{1024*128};

/// maximum amount of directory entries returned for a single read_dir request
std::size_t const max_read_dir_count{64};

/// sftp server backend that serves files from a local directory, everything outside the root is refused
class local_fs_server_backend : public sftp_server_backend {
public:
	local_fs_server_backend(logger&, std::filesystem::path root);

	void on_open_file(call_context, std::string_view path, open_mode mode, file_attributes attrs) override;
	void on_close_file(call_context, file_handle_view) override;
	void on_read_file(call_context, file_handle_view, std::uint64_t pos, std::uint32_t size) override;
	void on_write_file(call_context, file_handle_view, std::uint64_t pos, const_span data) override;

	void on_stat_file(call_context, file_handle_view) override;
	void on_setstat_file(call_context, file_handle_view, file_attributes) override;

	void on_open_dir(call_context, std::string_view path) override;
	void on_read_dir(call_context, dir_handle_view) override;
	void on_close_dir(call_context, dir_handle_view) override;

	void on_remove_file(call_context, std::string_view path) override;
	void on_rename(call_context, std::string_view old_path, std::string_view new_path) override;
	void on_mkdir(call_context, std::string_view path, file_attributes) override;
	void on_remove_dir(call_context, std::string_view path) override;

	void on_stat(call_context, std::string_view path, bool follow_symlinks) override;
	void on_setstat(call_context, std::string_view path, file_attributes) override;

	void on_readlink(call_context, std::string_view path) override;
	void on_symlink(call_context, std::string_view link, std::string_view path) override;

	void on_realpath(call_context, std::string_view path) override;

	void on_extended(call_context, std::string_view ext_request, const_span data) override;

private:
	struct file_entry {
		std::fstream stream;
		std::filesystem::path path;
	};

	struct dir_entry {
		std::filesystem::directory_iterator it;
	};

	/// resolve the client path, sends error and returns nullopt if the path is not acceptable
	std::optional<resolved_path> resolve(call_context, std::string_view path);
	bool send_errc(call_context, std::error_code const& ec);
	file_entry* find_file(call_context, file_handle_view);
	dir_entry* find_dir(call_context, dir_handle_view);
	void open_resolved_file(call_context, resolved_path const&, open_mode mode, file_attributes const& attrs);
	bool apply_attributes(std::filesystem::path const&, file_attributes const&, std::error_code& ec);

private:
	std::filesystem::path root_;
	std::map<std::string, file_entry, std::less<>> files_;
	std::map<std::string, dir_entry, std::less<>> dirs_;
	std::uint64_t handle_counter_{};
};

}

#endif
