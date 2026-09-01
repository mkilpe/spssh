
#include "server.hpp"

#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/service/names.hpp"
#include "ssh/services/sftp/local_fs_backend.hpp"
#include "ssh/services/sftp/sftp_session_channel.hpp"
#include "test/util/server_auth_service.hpp"

namespace securepath::ssh {
namespace {

/// connection service that accepts "session" channels which can be upgraded to sftp
class sftp_connection_service : public ssh_connection {
public:
	sftp_connection_service(transport_base& t, std::string sftp_root)
	: ssh_connection(t)
	{
		add_channel_type("session", [root = std::move(sftp_root)](transport_base& transport, channel_side_info info)
		{
			return std::make_unique<sftp::sftp_session_channel>(transport, info,
				[root, &transport]()
				{
					return std::make_shared<sftp::local_fs_server_backend>(transport.log(), root);
				});
		});
	}
};

}

ssh_test_server::ssh_test_server(test_server_config const& config, logger& log, out_buffer& buf, crypto_context& context)
: ssh_server(config, log, buf, context)
, config_(config)
{
}

std::unique_ptr<auth_service> ssh_test_server::construct_auth() {
	test_auth_data data;
	data.add_password("test", "some");
	data.add_pk("test", "SHA256:AJxI+SMrILxnTIinoWVeFhz3BGq9zH+VyOcH6IsJV/0");
	return std::make_unique<server_test_auth_service>(*this, config_.auth, std::move(data));
}

std::unique_ptr<ssh_service> ssh_test_server::construct_service(auth_info const& info) {
	std::unique_ptr<ssh_service> res;
	if(info.service == connection_service_name) {
		res = std::make_unique<sftp_connection_service>(*this, config_.sftp_root);
	}
	return res;
}

}
