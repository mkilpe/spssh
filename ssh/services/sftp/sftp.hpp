#ifndef SP_SSH_SFTP_HEADER
#define SP_SSH_SFTP_HEADER

#include "packet_types.hpp"
#include "ssh/common/types.hpp"

#include <optional>

namespace securepath::ssh::sftp {

// https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
std::uint32_t const sftp_version{3};
inline std::string_view sftp_subsystem_name{"sftp"};

struct ext_data_view {
	std::string_view type;
	std::string_view data;
};

struct ext_data {
	std::string type;
	std::string data;

	operator ext_data_view() const {
		return ext_data_view{type, data};
	}
};

using call_handle = std::uint32_t;
using file_handle = std::string;
using file_handle_view = std::string_view;

using dir_handle = std::string;
using dir_handle_view = std::string_view;

class sftp_error {
public:
	sftp_error() = default;
	sftp_error(std::uint32_t code, std::string_view msg)
	: code_((status_code)code)
	, message_(msg)
	{}

	status_code code() const { return code_; }
	std::string_view message() const { return message_; }

	/// this is an error if error code is not zero
	explicit operator bool() const {
		return code_ != 0;
	}

private:
	status_code code_{};
	std::string message_;
};

}

#endif