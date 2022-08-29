#include "sftp_server.hpp"
#include "packet_ser_impl.hpp"
#include "protocol.hpp"

namespace securepath::ssh::sftp {

sftp_server::sftp_server(std::unique_ptr<sftp_server_backend> backend, transport_base& transport, channel_side_info local, std::size_t buffer_size)
: channel(transport, local, buffer_size)
, backend_(std::move(backend))
{
	//t: parameterise this
	in_data_.resize(1024*256);

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
		if(backend_) {
			ext_data ed{};
			if(s.size() > packet.size()) {
				packet.reader().read(ed.type);
				packet.reader().read(ed.data);
			}
			backend_->on_init(version, ed);
		}
	} else {
		log_.log(logger::error, "Invalid sftp init packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

bool sftp_server::on_data(const_span s) {
	if(in_data_.size() - in_used_ < s.size()) {
		// cannot handle, buffer full
		return false;
	}

	copy(s, safe_subspan(in_data_, in_used_, s.size()));
	in_used_ += s.size();

	std::size_t used_size{};
	sftp_packet_type type{};
	do {
		std::uint32_t length{};
		auto span = safe_subspan(in_data_, used_size, in_used_ - used_size);
		type = decode_sftp_type(span, length);
		if(type) {
			switch(type) {
				case fxp_init: handle_init(span); break;

				default: break;
			};
			used_size += length;
		}
	} while(type != 0);

	if(used_size) {
		std::memmove(in_data_.data(), in_data_.data()+used_size, in_used_ - used_size);
	}

	adjust_in_window(used_size);
	return true;
}

void sftp_server::on_state_change() {
	if(state() == channel_state::closed && backend_) {
		backend_->detach();
		backend_.reset();
	}
}

void sftp_server::close(std::string_view error) {
	if(!error.empty()) {
		log_.log(logger::error, "sftp error: {}", error);
	}
	//transport_.set_error_and_disconnect(ssh_protocol_error);
	// try send close on error ?
}

bool sftp_server::send_version(std::uint32_t v, ext_data data) {
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
