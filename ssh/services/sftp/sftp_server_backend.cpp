#include "sftp_server_backend.hpp"

namespace securepath::ssh::sftp {

sftp_server_backend::sftp_server_backend(logger& l)
: log_(l)
{
}

void sftp_server_backend::attach(sftp_server_interface* s) {
	log_.log(logger::debug_trace, "sftp attach");
	s_ = s;
}

void sftp_server_backend::detach() {
	log_.log(logger::debug_trace, "sftp detach");
	s_ = nullptr;
}

void sftp_server_backend::on_init(std::uint32_t version, ext_data_view data) {
	SPSSH_ASSERT(s_, "invalid state");
	log_.log(logger::debug_trace, "sftp on_init [version={}, ext type={}]", version, data.type);
	if(!s_->send_version(std::min(version, sftp_version))) {
		s_->close("failed to send sftp version");
	}
}

}
