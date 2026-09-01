#include "sftp_session_channel.hpp"
#include "sftp.hpp"

namespace securepath::ssh::sftp {

sftp_session_channel::sftp_session_channel(transport_base& transport, channel_side_info local, sftp_server_backend_factory factory)
: channel(transport, local)
, backend_factory_(std::move(factory))
{
	SPSSH_ASSERT(backend_factory_, "sftp backend factory not set");
}

std::unique_ptr<channel_base> sftp_session_channel::on_request(std::string_view name, bool reply, const_span extra_data) {
	std::unique_ptr<channel_base> res;
	if(name == "subsystem") {
		res = on_subsystem_request(reply, extra_data);
	} else {
		// the base implementation sends failure for the request
		res = channel::on_request(name, reply, extra_data);
	}
	return res;
}

std::unique_ptr<channel_base> sftp_session_channel::on_subsystem_request(bool reply, const_span extra_data) {
	std::unique_ptr<channel_base> res;
	ssh_bf_reader r(extra_data);
	std::string_view subsystem;
	if(r.read(subsystem) && subsystem == sftp_subsystem_name) {
		log_.log(logger::info, "starting sftp subsystem");
		if(reply) {
			transport_.send_packet<ser::channel_success>(remote_info_.id);
		}
		// the returned channel replaces this one, must not use this any more after the move
		res = std::make_unique<sftp_server>(std::move(*this), backend_factory_());
	} else {
		log_.log(logger::debug, "unsupported subsystem requested [name={}]", subsystem);
		if(reply) {
			transport_.send_packet<ser::channel_failure>(remote_info_.id);
		}
	}
	return res;
}

}
