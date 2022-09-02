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

void sftp_server::handle_sftp_packet(sftp_packet_type type, const_span data) {
	// if we don't have backend attached any more, don't bother
	if(backend_) {
		switch(type) {
			case fxp_init: handle_init(data); break;

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
