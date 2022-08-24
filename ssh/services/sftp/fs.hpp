#ifndef SP_SSH_SFTP_FS_HEADER
#define SP_SSH_SFTP_FS_HEADER

namespace securepath::ssh::sftp {

// UTF-8 with '/' as directory separator
using path = std::string;
using path_view = std::string_view;

using file_handle = std::uint32_t;

class vfs {
public:
	virtual ~vfs() = default;

	virtual file_handle open_file(path_view const& name, file_mode mode, file_attributes attr) = 0;
	virtual void close_file(file_handle) = 0;

	virtual <data?> read_file(file_handle, std::uint64_t offset, std::uint64_t len) = 0;
	virtual std::uint64_t write_file(file_handle, std::uint64_t offset, const_span data) = 0;

	virtual bool remove_file(path_view) = 0;
	virtual bool rename_file(path_view old_name, path_view new_name) = 0;

	virtual bool create_dir(path_view, file_attributes) = 0;
	virtual bool remove_dir(path_view) = 0;
};

}

#endif