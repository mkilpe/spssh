#ifndef SP_SSH_SFTP_SERVER_BACKEND_HEADER
#define SP_SSH_SFTP_SERVER_BACKEND_HEADER

#include "sftp.hpp"
#include "ssh/common/logger.hpp"

namespace securepath::ssh::sftp {

class sftp_server_interface {
public:
	/// close the channel and set error if given
	virtual void close(std::string_view error = {}) = 0;

	/// send fxp_version packet
	virtual bool send_version(std::uint32_t version, ext_data_view = {}) = 0;

protected:
	~sftp_server_interface() = default;
};

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

protected:
	logger& log_;
	sftp_server_interface* s_{};
};

}

#endif