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

private:
	status_code code_{};
	std::string message_;
};

/// Result type for client side sftp calls
template<typename Data>
class sftp_result {
public:
	using data_type = Data;

	sftp_result(call_handle h, data_type d = {})
	: handle_(h)
	, data_(std::move(d))
	{}

	sftp_result(call_handle h, sftp_error e)
	: handle_(h)
	, error_(std::move(e))
	{}

	call_handle handle() const { return handle_; }

	explicit operator bool() const {
		return static_cast<bool>(data_);
	}

	sftp_error const& error() const {
		SPSSH_ASSERT(error_, "error not set");
		return *error_;
	}

	data_type const& data() const {
		SPSSH_ASSERT(data_, "data not set");
		return *data_;
	}

private:
	call_handle handle_;
	std::optional<data_type> data_;
	std::optional<sftp_error> error_;
};

}

#endif