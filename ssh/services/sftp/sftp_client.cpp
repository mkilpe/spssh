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
		log_.log(logger::info, "sending sftp subsystem request");
		send_subsystem_request(sftp_subsystem_name);
	}
	return true;
}

void sftp_client::on_request_success() {
	log_.log(logger::info, "subsystem request succeeded, sending sftp init");
	send_packet<init>(sftp_version);
}

void sftp_client::on_request_failure() {
	log_.log(logger::error, "Subsystem request for SFTP failed");
	transport_.set_error_and_disconnect(ssh_service_not_available);
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
		if(callback_->on_version(version, ed)) {
			log_.log(logger::info, "Successfully connected to SFTP server");
		} else {
			close("sftp version is not acceptable");
		}
	} else {
		log_.log(logger::error, "Invalid sftp version packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::handle_status(const_span s) {
	status_response::load packet(s);
	if(packet) {
		auto& [id, code, message, lang] = packet;
/*
		if(code == 0) {
			sftp_result res{id};
			do_callback(res);
		} else {
			sftp_result res{id, sftp_error{code, message}};
			do_callback(res);
		}*/
	} else {
		log_.log(logger::error, "Invalid sftp status packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::handle_handle(const_span s) {
}

void sftp_client::handle_data(const_span s) {
}

void sftp_client::handle_name(const_span s) {
}

void sftp_client::handle_attrs(const_span s) {

}

void sftp_client::handle_extended_reply(const_span s) {
}

void sftp_client::handle_sftp_packet(sftp_packet_type type, const_span data) {
	if(callback_) {
		switch(type) {
			case fxp_version:        handle_version(data);        break;
			case fxp_status:         handle_status(data);         break;
			case fxp_handle:         handle_handle(data);         break;
			case fxp_data:           handle_data(data);           break;
			case fxp_name:           handle_name(data);           break;
			case fxp_attrs:          handle_attrs(data);          break;
			case fxp_extended_reply: handle_extended_reply(data); break;
			default: break;
		};
	}
}

void sftp_client::close(std::string_view error) {
	sftp_common::close(error);
}

template<typename PacketType, sftp_packet_type Type, typename... Args>
call_handle sftp_client::send_sftp_packet(Args&&... args) {
	auto handle = ++sequence_;
	bool ret = send_packet<PacketType>(handle, std::forward<Args>(args)...);
	if(ret) {
		remote_calls_[handle] = call_data{fxp_open};
	}
	return ret ? handle : 0;
}

call_handle sftp_client::open_file(std::string_view path, open_mode mode, file_attributes attr) {
	byte_vector p;

	auto handle = ++sequence_;
	bool res = ser::serialise_to_vector<open_request>(p, handle, path, mode);

	if(res) {
		ssh_bf_writer res_w(p, p.size());
		attr.write(res_w);
		res = send_packet(p);
		remote_calls_[handle] = call_data{fxp_open};
	}
	return res ? handle : 0;
}

call_handle sftp_client::read_file(file_handle_view, std::uint64_t pos, std::uint32_t size) {
	return 0;
}

call_handle sftp_client::write_file(file_handle_view, std::uint64_t pos, const_span data) {
	return 0;
}

call_handle sftp_client::close_file(file_handle_view file_handle) {
	return send_sftp_packet<close_request, fxp_close>(file_handle);
}

call_handle sftp_client::open_dir(std::string_view path) {
	return send_sftp_packet<opendir_request, fxp_opendir>(path);
}

call_handle sftp_client::read_dir(dir_handle_view dir_handle) {
	return send_sftp_packet<readdir_request, fxp_readdir>(dir_handle);
}

call_handle sftp_client::close_dir(dir_handle_view dir_handle) {
	return send_sftp_packet<close_request, fxp_close>(dir_handle);
}

}
