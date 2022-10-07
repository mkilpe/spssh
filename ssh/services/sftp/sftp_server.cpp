#include "sftp_server.hpp"
#include "packet_ser_impl.hpp"
#include "protocol.hpp"

namespace securepath::ssh::sftp {

/*sftp_server::sftp_server(std::shared_ptr<sftp_server_backend> backend, transport_base& transport, channel_side_info local, std::size_t buffer_size)
: sftp_common(transport, local, buffer_size)
, backend_(std::move(backend))
{

	SPSSH_ASSERT(backend_, "sftp backend not set");
	backend_->attach(this);
}
*/

sftp_server::sftp_server(channel&& predecessor, std::shared_ptr<sftp_server_backend> backend)
: sftp_common(std::move(predecessor))
, backend_(std::move(backend))
{
	SPSSH_ASSERT(backend_, "sftp backend not set");
	backend_->attach(this);
}

sftp_server::~sftp_server() {
	if(backend_) {
		backend_->detach();
		backend_.reset();
	}
}

void sftp_server::handle_init(const_span s) {
	init::load packet(s);
	if(packet) {
		auto& [version] = packet;
		ext_data_view ed{};
		if(s.size() > packet.size()) {
			packet.reader().read(ed.type);
			packet.reader().read(ed.data);
		}
		backend_->on_init(version, ed);
	} else {
		log_.log(logger::error, "Invalid sftp init packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_server::handle_open(const_span) {

}

void sftp_server::handle_close(const_span) {

}

void sftp_server::handle_read(const_span) {

}

void sftp_server::handle_write(const_span) {

}

void sftp_server::handle_lstat(const_span) {

}

void sftp_server::handle_fstat(const_span) {

}

void sftp_server::handle_setstat(const_span) {

}

void sftp_server::handle_fsetstat(const_span) {

}

void sftp_server::handle_opendir(const_span) {

}

void sftp_server::handle_readdir(const_span) {

}

void sftp_server::handle_remove(const_span) {

}

void sftp_server::handle_mkdir(const_span) {

}

void sftp_server::handle_rmdir(const_span) {

}

void sftp_server::handle_realpath(const_span) {

}

void sftp_server::handle_stat(const_span) {

}

void sftp_server::handle_rename(const_span) {

}

void sftp_server::handle_readlink(const_span) {

}

void sftp_server::handle_symlink(const_span) {

}

void sftp_server::handle_extended(const_span) {

}


void sftp_server::handle_sftp_packet(sftp_packet_type type, const_span data) {
	// if we don't have backend attached any more, don't bother
	if(backend_) {
		switch(type) {
			case fxp_init    : handle_init(data);     break;
			case fxp_open    : handle_open(data);     break;
			case fxp_close   : handle_close(data);    break;
			case fxp_read    : handle_read(data);     break;
			case fxp_write   : handle_write(data);    break;
			case fxp_lstat   : handle_lstat(data);    break;
			case fxp_fstat   : handle_fstat(data);    break;
			case fxp_setstat : handle_setstat(data);  break;
			case fxp_fsetstat: handle_fsetstat(data); break;
			case fxp_opendir : handle_opendir(data);  break;
			case fxp_readdir : handle_readdir(data);  break;
			case fxp_remove  : handle_remove(data);   break;
			case fxp_mkdir   : handle_mkdir(data);    break;
			case fxp_rmdir   : handle_rmdir(data);    break;
			case fxp_realpath: handle_realpath(data); break;
			case fxp_stat    : handle_stat(data);     break;
			case fxp_rename  : handle_rename(data);   break;
			case fxp_readlink: handle_readlink(data); break;
			case fxp_symlink : handle_symlink(data);  break;
			case fxp_extended: handle_extended(data); break;
			default: break;
		};
	}
}

void sftp_server::on_state_change() {
	if(state() == channel_state::closed && backend_) {
		backend_->detach();
		backend_.reset();
	}
}

void sftp_server::close(std::string_view error) {
	sftp_common::close(error);
}

bool sftp_server::send_version(std::uint32_t v, ext_data_view data) {
	byte_vector p;

	bool res = ser::serialise_to_vector<version>(p, v);

	if(res) {
		if(!data.type.empty()) {
			ssh_bf_writer res_w(p, p.size());
			res_w.write(data.type);
			res_w.write(data.data);
		}
		res = send_packet(p);
	}
	return res;
}

}
