#ifndef SP_SSH_SFTP_FILE_ATTRIBUTES_HEADER
#define SP_SSH_SFTP_FILE_ATTRIBUTES_HEADER

#include "sftp.hpp"
#include "ssh/core/ssh_binary_util.hpp"

namespace securepath::ssh::sftp {

struct file_attributes {
	/// file size in bytes
	std::optional<std::uint64_t> size;
	/// Unix-like user identifier
	std::optional<std::uint32_t> uid;
	/// Unix-like group identifier
	std::optional<std::uint32_t> gid;
	/// bit mask of file permissions as defined by posix
	std::optional<std::uint32_t> permissions;
	/// access time in seconds from Jan 1, 1970 UTC
	std::optional<std::uint32_t> atime;
	/// modification time in seconds from Jan 1, 1970 UTC
	std::optional<std::uint32_t> mtime;
	/// general extensions
	std::vector<ext_data> extended;

	/// return the flags for attributes hold here
	attribute_flags flags() const;

	/// deserialise attributes
	bool read(ssh_bf_reader&);
	/// deserialise attributes without reading the flags in front
	bool read(ssh_bf_reader&, std::uint32_t flags);
	bool write(ssh_bf_writer&);
};

}

#endif