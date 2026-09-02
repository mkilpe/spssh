#include "sftp_fixtures.hpp"

#include "ssh/core/connection/conn_protocol.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/services/sftp/packet_ser.hpp"
#include "ssh/services/sftp/packet_ser_impl.hpp"

namespace securepath::ssh::test {

std::optional<out_packet_record> sftp_record_transport::alloc_out_packet(std::size_t data_size) {
	buf_.resize(data_size);
	out_packet_record rec{};
	rec.size = data_size;
	rec.payload_size = data_size;
	rec.data = span(buf_);
	rec.data_buffer = span(buf_);
	return rec;
}

bool sftp_record_transport::write_alloced_out_packet(out_packet_record const& r) {
	sent.push_back(byte_vector(r.data.begin(), r.data.begin() + r.payload_size));
	return true;
}

byte_vector channel_data_stream(std::vector<byte_vector> const& sent) {
	byte_vector res;
	for(auto&& v : sent) {
		if(!v.empty() && std::uint8_t(v[0]) == ssh_channel_data) {
			ser::channel_data::load packet(ser::match_type_t, v);
			if(packet) {
				auto& [id, data] = packet;
				auto s = to_span(data);
				res.insert(res.end(), s.begin(), s.end());
			}
		}
	}
	return res;
}

std::vector<sftp_packet_data> parse_sftp_packets(const_span stream) {
	std::vector<sftp_packet_data> res;
	std::size_t const header_size = 5;
	std::size_t pos{};
	bool more = true;
	while(more) {
		more = false;
		std::uint32_t length{};
		auto type = sftp::decode_sftp_type(safe_subspan(stream, pos), length);
		if(type && length) {
			auto payload = safe_subspan(stream, pos + header_size, length - 1);
			res.push_back({type, byte_vector(payload.begin(), payload.end())});
			pos += header_size + length - 1;
			more = true;
		}
	}
	return res;
}

// --- recording_client_callback ---

bool recording_client_callback::on_version(std::uint32_t v, std::vector<sftp::ext_data_view> const& ext) {
	version = v;
	for(auto&& e : ext) {
		extensions.push_back(sftp::ext_data{std::string(e.type), std::string(e.data)});
	}
	events.push_back({"version", 0});
	return accept_version;
}

void recording_client_callback::on_failure(sftp::call_handle h, sftp::sftp_error err) {
	events.push_back({"failure", h});
	last_error = std::move(err);
}

void recording_client_callback::on_open_file(sftp::call_handle h, sftp::open_file_data r) {
	events.push_back({"open_file", h});
	last_file = std::move(r.handle);
}

void recording_client_callback::on_read_file(sftp::call_handle h, sftp::read_file_data r) {
	events.push_back({"read_file", h});
	last_data.assign(r.data.begin(), r.data.end());
}

void recording_client_callback::on_write_file(sftp::call_handle h, sftp::write_file_data) {
	events.push_back({"write_file", h});
}

void recording_client_callback::on_close_file(sftp::call_handle h, sftp::close_file_data) {
	events.push_back({"close_file", h});
}

void recording_client_callback::on_stat_file(sftp::call_handle h, sftp::state_file_data r) {
	events.push_back({"stat_file", h});
	last_attrs = std::move(r.attrs);
}

void recording_client_callback::on_setstat_file(sftp::call_handle h, sftp::setstate_file_data) {
	events.push_back({"setstat_file", h});
}

void recording_client_callback::on_open_dir(sftp::call_handle h, sftp::open_dir_data r) {
	events.push_back({"open_dir", h});
	last_dir = std::move(r.handle);
}

void recording_client_callback::on_read_dir(sftp::call_handle h, sftp::read_dir_data r) {
	events.push_back({"read_dir", h});
	last_files.clear();
	for(auto&& f : r.files) {
		last_files.push_back(sftp::file_info{std::string(f.filename), std::string(f.longname), f.attrs});
	}
}

void recording_client_callback::on_close_dir(sftp::call_handle h, sftp::close_dir_data) {
	events.push_back({"close_dir", h});
}

void recording_client_callback::on_remove_file(sftp::call_handle h, sftp::remove_file_data) {
	events.push_back({"remove_file", h});
}

void recording_client_callback::on_rename(sftp::call_handle h, sftp::rename_data) {
	events.push_back({"rename", h});
}

void recording_client_callback::on_mkdir(sftp::call_handle h, sftp::mkdir_data) {
	events.push_back({"mkdir", h});
}

void recording_client_callback::on_remove_dir(sftp::call_handle h, sftp::remove_dir_data) {
	events.push_back({"remove_dir", h});
}

void recording_client_callback::on_stat(sftp::call_handle h, sftp::stat_data r) {
	events.push_back({"stat", h});
	last_attrs = std::move(r.attrs);
}

void recording_client_callback::on_setstat(sftp::call_handle h, sftp::setstat_data) {
	events.push_back({"setstat", h});
}

void recording_client_callback::on_readlink(sftp::call_handle h, sftp::readlink_data r) {
	events.push_back({"readlink", h});
	last_path = std::string(r.path);
}

void recording_client_callback::on_symlink(sftp::call_handle h, sftp::symlink_data) {
	events.push_back({"symlink", h});
}

void recording_client_callback::on_realpath(sftp::call_handle h, sftp::realpath_data r) {
	events.push_back({"realpath", h});
	last_path = std::string(r.path);
}

void recording_client_callback::on_extended(sftp::call_handle h, sftp::extended_data r) {
	events.push_back({"extended", h});
	last_data.assign(r.data.begin(), r.data.end());
}

// --- recording_server_backend ---

void recording_server_backend::on_init(std::uint32_t version, std::vector<sftp::ext_data_view> const& data) {
	init_version = version;
	for(auto&& e : data) {
		extensions.push_back(sftp::ext_data{std::string(e.type), std::string(e.data)});
	}
	events.push_back({"init", 0});
	if(auto_version) {
		sftp::sftp_server_backend::on_init(version, data);
	}
}

void recording_server_backend::on_open_file(sftp::call_context ctx, std::string_view path, sftp::open_mode mode, sftp::file_attributes attrs) {
	events.push_back({"open_file", ctx});
	last_path = std::string(path);
	last_mode = mode;
	last_attrs = std::move(attrs);
}

void recording_server_backend::on_close_file(sftp::call_context ctx, sftp::file_handle_view h) {
	events.push_back({"close_file", ctx});
	last_handle = std::string(h);
}

void recording_server_backend::on_read_file(sftp::call_context ctx, sftp::file_handle_view h, std::uint64_t pos, std::uint32_t size) {
	events.push_back({"read_file", ctx});
	last_handle = std::string(h);
	last_pos = pos;
	last_size = size;
}

void recording_server_backend::on_write_file(sftp::call_context ctx, sftp::file_handle_view h, std::uint64_t pos, const_span data) {
	events.push_back({"write_file", ctx});
	last_handle = std::string(h);
	last_pos = pos;
	last_data.assign(data.begin(), data.end());
}

void recording_server_backend::on_stat_file(sftp::call_context ctx, sftp::file_handle_view h) {
	events.push_back({"stat_file", ctx});
	last_handle = std::string(h);
}

void recording_server_backend::on_setstat_file(sftp::call_context ctx, sftp::file_handle_view h, sftp::file_attributes attrs) {
	events.push_back({"setstat_file", ctx});
	last_handle = std::string(h);
	last_attrs = std::move(attrs);
}

void recording_server_backend::on_open_dir(sftp::call_context ctx, std::string_view path) {
	events.push_back({"open_dir", ctx});
	last_path = std::string(path);
}

void recording_server_backend::on_read_dir(sftp::call_context ctx, sftp::dir_handle_view h) {
	events.push_back({"read_dir", ctx});
	last_handle = std::string(h);
}

void recording_server_backend::on_close_dir(sftp::call_context ctx, sftp::dir_handle_view h) {
	events.push_back({"close_dir", ctx});
	last_handle = std::string(h);
}

void recording_server_backend::on_remove_file(sftp::call_context ctx, std::string_view path) {
	events.push_back({"remove_file", ctx});
	last_path = std::string(path);
}

void recording_server_backend::on_rename(sftp::call_context ctx, std::string_view old_path, std::string_view new_path) {
	events.push_back({"rename", ctx});
	last_path = std::string(old_path);
	last_target = std::string(new_path);
}

void recording_server_backend::on_mkdir(sftp::call_context ctx, std::string_view path, sftp::file_attributes attrs) {
	events.push_back({"mkdir", ctx});
	last_path = std::string(path);
	last_attrs = std::move(attrs);
}

void recording_server_backend::on_remove_dir(sftp::call_context ctx, std::string_view path) {
	events.push_back({"remove_dir", ctx});
	last_path = std::string(path);
}

void recording_server_backend::on_stat(sftp::call_context ctx, std::string_view path, bool follow_symlinks) {
	events.push_back({"stat", ctx});
	last_path = std::string(path);
	last_follow = follow_symlinks;
}

void recording_server_backend::on_setstat(sftp::call_context ctx, std::string_view path, sftp::file_attributes attrs) {
	events.push_back({"setstat", ctx});
	last_path = std::string(path);
	last_attrs = std::move(attrs);
}

void recording_server_backend::on_readlink(sftp::call_context ctx, std::string_view path) {
	events.push_back({"readlink", ctx});
	last_path = std::string(path);
}

void recording_server_backend::on_symlink(sftp::call_context ctx, std::string_view link, std::string_view path) {
	events.push_back({"symlink", ctx});
	last_path = std::string(link);
	last_target = std::string(path);
}

void recording_server_backend::on_realpath(sftp::call_context ctx, std::string_view path) {
	events.push_back({"realpath", ctx});
	last_path = std::string(path);
}

void recording_server_backend::on_extended(sftp::call_context ctx, std::string_view ext_request, const_span data) {
	events.push_back({"extended", ctx});
	last_ext_request = std::string(ext_request);
	last_data.assign(data.begin(), data.end());
}

channel make_established_channel(transport_base& t, std::uint32_t remote_window, std::uint32_t remote_max_packet) {
	channel ch(t, channel_side_info{1, 2*1024*1024, 32768});
	static_cast<channel_base&>(ch).on_open(channel_side_info{7, remote_window, remote_max_packet}, {});
	return ch;
}

}
