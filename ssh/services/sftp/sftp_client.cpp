#include "sftp_client.hpp"
#include "sftp.hpp"
#include "packet_ser_impl.hpp"
#include "protocol.hpp"

namespace securepath::ssh::sftp {

// the actual packet uses just fxp_close but we need to differentiate for result
std::uint16_t const fxp_closedir = 512;

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

void sftp_client::call_status_result(call_handle id, sftp_error err) {
	if(!err) {
		auto it = remote_calls_.find(id);
		if(it != remote_calls_.end()) {
			switch(it->second.type) {
				// these types don't get any data as response and hence the status packet is used
				case fxp_write:    callback_->on_write_file(id, write_file_data{}); break;
				case fxp_close:    callback_->on_close_file(id, close_file_data{}); break;
				case fxp_closedir: callback_->on_close_dir(id, close_dir_data{}); break;
				case fxp_fsetstat: callback_->on_setstat_file(id, setstate_file_data{}); break;
				case fxp_remove:   callback_->on_remove_file(id, remove_file_data{}); break;
				case fxp_rename:   callback_->on_rename(id, rename_data{}); break;
				case fxp_mkdir:    callback_->on_mkdir(id, mkdir_data{}); break;
				case fxp_rmdir:    callback_->on_remove_dir(id, remove_dir_data{}); break;
				case fxp_setstat:  callback_->on_setstat(id, setstat_data{}); break;
				case fxp_symlink:  callback_->on_symlink(id, symlink_data{}); break;
				default: log_.log(logger::debug_trace, "Invalid status packet with no error for {} [call={}]", it->second.type, id); break;
			}
			remote_calls_.erase(it);
		} else {
			log_.log(logger::debug_trace, "Status packet with to matching call id [call={}]", id);
		}
	} else {
		log_.log(logger::debug_trace, "sftp_client::call_status_result failure [code={}, msg={}]", err.code(), err.message());

		remote_calls_.erase(id);
		callback_->on_failure(id, std::move(err));
	}
}

void sftp_client::handle_status(const_span s) {
	log_.log(logger::debug_trace, "sftp_client::handle_status");
	status_response::load packet(s);
	if(packet) {
		auto& [id, code, message, lang] = packet;
		call_status_result(id, sftp_error{code, message});
	} else {
		log_.log(logger::error, "Invalid sftp status packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::call_handle_result(call_handle id, std::string_view handle) {
	auto it = remote_calls_.find(id);
	if(it != remote_calls_.end()) {
		switch(it->second.type) {
			case fxp_open: callback_->on_open_file(id, open_file_data{file_handle{handle}}); break;
			case fxp_opendir: callback_->on_open_dir(id, open_dir_data{dir_handle{handle}}); break;
			default:
			{
				log_.log(logger::debug_trace, "Invalid handle packet for {} [call={}]", it->second.type, id);
				callback_->on_failure(id, sftp_error{status_code::fx_failure, "Wrong result packet type"});
				break;
			}
		}
		remote_calls_.erase(it);
	} else {
		log_.log(logger::debug_trace, "Handle packet with to matching call id [call={}]", id);
	}
}

void sftp_client::handle_handle(const_span s) {
	handle_response::load packet(s);
	if(packet) {
		auto& [id, handle] = packet;
		call_handle_result(id, handle);
	} else {
		log_.log(logger::error, "Invalid sftp handle packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::call_data_result(call_handle id, std::string_view data) {
	auto it = remote_calls_.find(id);
	if(it != remote_calls_.end()) {
		switch(it->second.type) {
			case fxp_read: callback_->on_read_file(id, read_file_data{to_span(data)}); break;
			default:
			{
				log_.log(logger::debug_trace, "Invalid data packet for {} [call={}]", it->second.type, id);
				callback_->on_failure(id, sftp_error{status_code::fx_failure, "Wrong result packet type"});
				break;
			}
		}
		remote_calls_.erase(it);
	} else {
		log_.log(logger::debug_trace, "Data packet with to matching call id [call={}]", id);
	}
}

void sftp_client::handle_data(const_span s) {
	data_response::load packet(s);
	if(packet) {
		auto& [id, data] = packet;
		call_data_result(id, data);
	} else {
		log_.log(logger::error, "Invalid sftp data packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::call_name_result(call_handle id, std::vector<file_info> files) {
	auto it = remote_calls_.find(id);
	if(it != remote_calls_.end()) {
		switch(it->second.type) {
			case fxp_readdir: callback_->on_read_dir(id, read_dir_data{std::move(files)}); break;
			case fxp_readlink:
			{
				if(files.size() == 1) {
					callback_->on_readlink(id, readlink_data{files.front().filename});
				} else {
					callback_->on_failure(id, sftp_error{status_code::fx_failure, "Wrong result packet type"});
				}
				break;
			}
			case fxp_realpath:
			{
				if(files.size() == 1) {
					callback_->on_realpath(id, realpath_data{files.front().filename});
				} else {
					callback_->on_failure(id, sftp_error{status_code::fx_failure, "Wrong result packet type"});
				}
				break;
			}
			default:
			{
				log_.log(logger::debug_trace, "Invalid name packet for {} [call={}]", it->second.type, id);
				callback_->on_failure(id, sftp_error{status_code::fx_failure, "Wrong result packet type"});
				break;
			}
		}
		remote_calls_.erase(it);
	} else {
		log_.log(logger::debug_trace, "Name packet with to matching call id [call={}]", id);
	}
}

void sftp_client::handle_name(const_span s) {
	name_response::load packet(s);
	if(packet) {
		auto& [id, count] = packet;
		auto& reader = packet.reader();

		std::vector<file_info> files;
		files.reserve(count);

		for(std::uint32_t i = 0; i != count; ++i) {
			std::string_view filename, longname;
			file_attributes attr;
			if(reader.read(filename)
				&& reader.read(longname)
				&& attr.read(reader))
			{
				files.push_back(file_info{filename, longname, std::move(attr)});
			} else {
				log_.log(logger::error, "Invalid sftp name packet");
				transport_.set_error_and_disconnect(ssh_protocol_error);
				return;
			}
		}

		call_name_result(id, std::move(files));

	} else {
		log_.log(logger::error, "Invalid sftp name packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::call_attr_result(call_handle id, file_attributes attrs) {
	auto it = remote_calls_.find(id);
	if(it != remote_calls_.end()) {
		switch(it->second.type) {
			// stats
			case fxp_stat: [[fallthrough]];
			case fxp_lstat: callback_->on_stat(id, stat_data{std::move(attrs)}); break;
			case fxp_fstat: callback_->on_stat_file(id, state_file_data{std::move(attrs)}); break;
			default:
			{
				log_.log(logger::debug_trace, "Invalid attrs packet for {} [call={}]", it->second.type, id);
				callback_->on_failure(id, sftp_error{status_code::fx_failure, "Wrong result packet type"});
				break;
			}
		}
		remote_calls_.erase(it);
	} else {
		log_.log(logger::debug_trace, "Attrs packet with to matching call id [call={}]", id);
	}
}

void sftp_client::handle_attrs(const_span s) {
	attrs_response::load packet(s);
	if(packet) {
		auto& [id] = packet;
		file_attributes attr;
		if(attr.read(packet.reader())) {
			call_attr_result(id, std::move(attr));
		} else {
			log_.log(logger::error, "Invalid sftp attrs packet");
			transport_.set_error_and_disconnect(ssh_protocol_error);
		}
	} else {
		log_.log(logger::error, "Invalid sftp attrs packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::handle_extended_reply(const_span s) {
	extended_reply_response::load packet(s);
	if(packet) {
		auto& [id] = packet;
		auto it = remote_calls_.find(id);
		if(it != remote_calls_.end()) {
			if(it->second.type == fxp_extended) {
				on_extended_reply(id, packet.reader());
			} else {
				log_.log(logger::debug_trace, "Invalid extended reply packet for {} [call={}]", it->second.type, id);
			}
			remote_calls_.erase(it);
		} else {
			log_.log(logger::debug_trace, "Extended reply packet with to matching call id [call={}]", id);
		}
	} else {
		log_.log(logger::error, "Invalid sftp status packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_client::on_extended_reply(call_handle id, ssh_bf_reader& r) {
	// one can override this if implementing extensions
	callback_->on_extended(id, extended_data{r.rest_of_span()});
}

void sftp_client::handle_sftp_packet(sftp_packet_type type, const_span data) {
	log_.log(logger::debug_trace, "client handle_sftp_packet [type={}]", int(type));
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

template<typename PacketType, std::uint16_t Type, typename... Args>
call_handle sftp_client::send_sftp_packet(Args&&... args) {
	auto handle = ++sequence_;
	bool ret = send_packet<PacketType>(handle, std::forward<Args>(args)...);
	if(ret) {
		remote_calls_[handle] = call_data{Type};
	} else {
		log_.log(logger::debug, "Failed to send sftp packet");
	}
	return ret ? handle : 0;
}

template<typename PacketType, std::uint16_t fxp_type, typename... Args>
call_handle sftp_client::send_packet_attr_helper(file_attributes const& attrs, Args&&... args) {
	byte_vector p;

	auto handle = ++sequence_;
	bool res = ser::serialise_to_vector<PacketType>(p, handle, std::forward<Args>(args)...);

	if(res) {
		ssh_bf_writer res_w(p, p.size());
		attrs.write(res_w);
		res = send_packet(p);
		remote_calls_[handle] = call_data{fxp_type};
	}
	return res ? handle : 0;
}

call_handle sftp_client::open_file(std::string_view path, open_mode mode, file_attributes const& attr) {
	log_.log(logger::debug_trace, "open_file");
	return send_packet_attr_helper<open_request, fxp_open>(attr, path, mode);
}

call_handle sftp_client::read_file(file_handle_view handle, std::uint64_t pos, std::uint32_t size) {
	log_.log(logger::debug_trace, "read_file");
	return send_sftp_packet<read_request, fxp_read>(handle, pos, size);
}

call_handle sftp_client::write_file(file_handle_view handle, std::uint64_t pos, const_span data) {
	log_.log(logger::debug_trace, "write_file");
	return send_sftp_packet<write_request, fxp_write>(handle, pos, to_string_view(data));
}

call_handle sftp_client::close_file(file_handle_view handle) {
	log_.log(logger::debug_trace, "close_file");
	return send_sftp_packet<close_request, fxp_close>(handle);
}

call_handle sftp_client::stat_file(file_handle_view handle) {
	log_.log(logger::debug_trace, "stat_file");
	return send_sftp_packet<fstat_request, fxp_fstat>(handle);
}

call_handle sftp_client::setstat_file(file_handle_view file_handle, file_attributes const& attrs) {
	log_.log(logger::debug_trace, "setstat_file");
	return send_packet_attr_helper<fsetstat_request, fxp_fsetstat>(attrs, file_handle);
}

call_handle sftp_client::open_dir(std::string_view path) {
	log_.log(logger::debug_trace, "open_dir: {}", path);
	return send_sftp_packet<opendir_request, fxp_opendir>(path);
}

call_handle sftp_client::read_dir(dir_handle_view dir_handle) {
	log_.log(logger::debug_trace, "read_dir");
	return send_sftp_packet<readdir_request, fxp_readdir>(dir_handle);
}

call_handle sftp_client::close_dir(dir_handle_view dir_handle) {
	log_.log(logger::debug_trace, "close_dir");
	return send_sftp_packet<close_request, fxp_closedir>(dir_handle);
}

call_handle sftp_client::remove_file(std::string_view path) {
	log_.log(logger::debug_trace, "remove_file");
	return send_sftp_packet<remove_request, fxp_remove>(path);
}

call_handle sftp_client::rename(std::string_view old_path, std::string_view new_path) {
	log_.log(logger::debug_trace, "rename");
	return send_sftp_packet<rename_request, fxp_rename>(old_path, new_path);
}

call_handle sftp_client::mkdir(std::string_view path, file_attributes const& attrs) {
	log_.log(logger::debug_trace, "mkdir");
	return send_packet_attr_helper<mkdir_request, fxp_mkdir>(attrs, path);
}

call_handle sftp_client::remove_dir(std::string_view path) {
	log_.log(logger::debug_trace, "remove_dir");
	return send_sftp_packet<rmdir_request, fxp_rmdir>(path);
}

call_handle sftp_client::stat(std::string_view path, bool follow_symlinks) {
	log_.log(logger::debug_trace, "stat [follow_symlinks={}]", follow_symlinks);
	return follow_symlinks ?
		send_sftp_packet<stat_request, fxp_stat>(path) :
		send_sftp_packet<lstat_request, fxp_lstat>(path);
}

call_handle sftp_client::setstat(std::string_view path, file_attributes const& attrs) {
	log_.log(logger::debug_trace, "setstat");
	return send_packet_attr_helper<setstat_request, fxp_setstat>(attrs, path);
}

call_handle sftp_client::readlink(std::string_view path) {
	log_.log(logger::debug_trace, "readlink");
	return send_sftp_packet<readlink_request, fxp_readlink>(path);
}

call_handle sftp_client::symlink(std::string_view link, std::string_view path) {
	log_.log(logger::debug_trace, "symlink");
	return send_sftp_packet<symlink_request, fxp_symlink>(link, path);
}

call_handle sftp_client::realpath(std::string_view path) {
	log_.log(logger::debug_trace, "realpath");
	return send_sftp_packet<realpath_request, fxp_realpath>(path);
}

call_handle sftp_client::extended(std::string_view ext_request, const_span data) {
	byte_vector p;

	auto handle = ++sequence_;
	bool res = ser::serialise_to_vector<extended_request>(p, handle, ext_request);

	if(res) {
		ssh_bf_writer res_w(p, p.size());
		res_w.write(to_string_view(data));
		res = send_packet(p);
		remote_calls_[handle] = call_data{fxp_extended};
	}
	return res ? handle : 0;
}

}
