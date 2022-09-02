#include "sftp_client.hpp"
#include "sftp.hpp"
#include "packet_ser_impl.hpp"
#include "protocol.hpp"

namespace securepath::ssh::sftp {

sftp_client::sftp_client(std::shared_ptr<sftp_client_callback> callback, transport_base& transport, channel_side_info local, std::size_t buffer_size)
: sftp_common(transport, local, buffer_size)
, callback_(callback)
{
}

bool sftp_client::on_confirm(channel_side_info remote, const_span extra_data) {
	if(channel::on_confirm(remote, extra_data)) {
		//send_packet<init>(sftp_version);
		//t: send channel request and only after that the init packet
	}
	return true;
}

void sftp_client::handle_version(const_span s) {
	version::load packet(s);
	if(packet) {
		auto& [version] = packet;
		ext_data_view ed{};
		if(s.size() > packet.size()) {
			packet.reader().read(ed.type);
			packet.reader().read(ed.data);
		}
		if(!callback_->on_version(version, ed)) {
			close("sftp version is not acceptable");
		}
	} else {
		log_.log(logger::error, "Invalid sftp version packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::handle_sftp_packet(sftp_packet_type type, const_span data) {
	if(callback_) {
		switch(type) {
			case fxp_version: handle_version(data); break;
			default: break;
		};
	}
}

void sftp_client::close(std::string_view error) {
	sftp_common::close(error);
}

call_handle sftp_client::open_file(std::string_view path, open_mode mode, file_attributes attr) {
	byte_vector p;

	auto handle = ++sequence_;
	bool res = ser::serialise_to_vector<open_request>(p, handle, path, mode);

	if(res) {
		ssh_bf_writer res_w(p, p.size());
		attr.write(res_w);
		res = send_packet(p);
	}
	return res ? handle : 0;
}

call_handle sftp_client::read_file(file_handle_view, std::uint64_t pos, std::uint32_t size) {
	return 0;
}

call_handle sftp_client::write_file(file_handle_view, std::uint64_t pos, const_span data) {
	return 0;
}

call_handle sftp_client::close_file(file_handle_view) {
	return 0;
}

}
