#ifndef SP_SSH_SFTP_SESSION_CHANNEL_HEADER
#define SP_SSH_SFTP_SESSION_CHANNEL_HEADER

#include "sftp_server.hpp"

#include <functional>

namespace securepath::ssh::sftp {

/// factory to create a backend for each sftp session
using sftp_server_backend_factory = std::function<std::shared_ptr<sftp_server_backend>()>;

/// Server side "session" channel that upgrades itself to sftp_server when the sftp subsystem is requested
class sftp_session_channel : public channel {
public:
	sftp_session_channel(transport_base&, channel_side_info local, sftp_server_backend_factory);

protected:
	std::unique_ptr<channel_base> on_request(std::string_view name, bool reply, const_span extra_data) override;

private:
	std::unique_ptr<channel_base> on_subsystem_request(bool reply, const_span extra_data);

private:
	sftp_server_backend_factory backend_factory_;
};

}

#endif
