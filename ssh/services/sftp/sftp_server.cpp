#include "sftp_server.hpp"
#include "packet_ser_impl.hpp"
#include "protocol.hpp"

namespace securepath::ssh::sftp {

std::uint64_t constexpr call_id_mask = 0xFFFFFFFFULL;

static std::uint32_t call_id(call_context ctx) {
	return std::uint32_t(ctx & call_id_mask);
}

static call_context to_call_context(std::uint32_t id) {
	return call_context{id};
}

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

template<typename Packet, typename Func>
void sftp_server::handle_packet_helper(Func f, const_span s) {
	typename Packet::load packet(s);
	if(packet) {
		f(packet);
	} else {
		log_.log(logger::error, "Invalid sftp packet: {}", typeid(Packet).name());
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
}

void sftp_server::handle_init(const_span s) {
	handle_packet_helper<init>([this](auto& p)
		{
			auto& [version] = p;
			ext_data_view ed{};
			auto& reader = p.reader();
			if(!reader.rest_of_span().empty()) {
				reader.read(ed.type);
				reader.read(ed.data);
			}
			backend_->on_init(version, ed);
		}, s);
}

void sftp_server::handle_open(const_span s) {
	handle_packet_helper<open_request>([this](auto& p)
		{
			auto& [id, filename, flags] = p;
			auto& r = p.reader();
			file_attributes attrs;
			if(attrs.read(r)) {
				backend_->on_open_file(to_call_context(id), filename, open_mode{flags}, std::move(attrs));
			} else {
				log_.log(logger::error, "Invalid sftp open packet");
				transport_.set_error_and_disconnect(ssh_protocol_error);
			}
		}, s);
}

void sftp_server::handle_close(const_span s) {
	handle_packet_helper<close_request>([this](auto& p)
		{
			auto& [id, handle] = p;
			backend_->on_close_file(to_call_context(id), handle);
		}, s);
}

void sftp_server::handle_read(const_span s) {
	handle_packet_helper<read_request>([this](auto& p)
		{
			auto& [id, handle, offset, length] = p;
			backend_->on_read_file(to_call_context(id), handle, offset, length);
		}, s);
}

void sftp_server::handle_write(const_span s) {
	handle_packet_helper<write_request>([this](auto& p)
		{
			auto& [id, handle, offset, data] = p;
			backend_->on_write_file(to_call_context(id), handle, offset, to_span(data));
		}, s);
}

void sftp_server::handle_lstat(const_span s) {
	handle_packet_helper<lstat_request>([this](auto& p)
		{
			auto& [id, path] = p;
			backend_->on_stat(to_call_context(id), path, false);
		}, s);
}

void sftp_server::handle_fstat(const_span s) {
	handle_packet_helper<fstat_request>([this](auto& p)
		{
			auto& [id, handle] = p;
			backend_->on_stat_file(to_call_context(id), handle);
		}, s);
}

void sftp_server::handle_setstat(const_span s) {
	handle_packet_helper<setstat_request>([this](auto& p)
		{
			auto& [id, path] = p;
			auto& r = p.reader();
			file_attributes attrs;
			if(attrs.read(r)) {
				backend_->on_setstat_file(to_call_context(id), path, std::move(attrs));
			} else {
				log_.log(logger::error, "Invalid sftp setstat packet");
				transport_.set_error_and_disconnect(ssh_protocol_error);
			}
		}, s);
}

void sftp_server::handle_fsetstat(const_span s) {
	handle_packet_helper<fsetstat_request>([this](auto& p)
		{
			auto& [id, handle] = p;
			auto& r = p.reader();
			file_attributes attrs;
			if(attrs.read(r)) {
				backend_->on_setstat_file(to_call_context(id), handle, std::move(attrs));
			} else {
				log_.log(logger::error, "Invalid sftp fsetstat packet");
				transport_.set_error_and_disconnect(ssh_protocol_error);
			}
		}, s);
}

void sftp_server::handle_opendir(const_span s) {
	handle_packet_helper<opendir_request>([this](auto& p)
		{
			auto& [id, path] = p;
			backend_->on_open_dir(to_call_context(id), path);
		}, s);
}

void sftp_server::handle_readdir(const_span s) {
	handle_packet_helper<readdir_request>([this](auto& p)
		{
			auto& [id, handle] = p;
			backend_->on_read_dir(to_call_context(id), handle);
		}, s);
}

void sftp_server::handle_remove(const_span s) {
	handle_packet_helper<remove_request>([this](auto& p)
		{
			auto& [id, filename] = p;
			backend_->on_remove_file(to_call_context(id), filename);
		}, s);
}

void sftp_server::handle_mkdir(const_span s) {
	handle_packet_helper<mkdir_request>([this](auto& p)
		{
			auto& [id, path] = p;
			auto& r = p.reader();
			file_attributes attrs;
			if(attrs.read(r)) {
				backend_->on_mkdir(to_call_context(id), path, std::move(attrs));
			} else {
				log_.log(logger::error, "Invalid sftp mkdir packet");
				transport_.set_error_and_disconnect(ssh_protocol_error);
			}
		}, s);
}

void sftp_server::handle_rmdir(const_span s) {
	handle_packet_helper<rmdir_request>([this](auto& p)
		{
			auto& [id, path] = p;
			backend_->on_remove_dir(to_call_context(id), path);
		}, s);
}

void sftp_server::handle_realpath(const_span s) {
	handle_packet_helper<realpath_request>([this](auto& p)
		{
			auto& [id, path] = p;
			backend_->on_realpath(to_call_context(id), path);
		}, s);
}

void sftp_server::handle_stat(const_span s) {
	handle_packet_helper<stat_request>([this](auto& p)
		{
			auto& [id, path] = p;
			backend_->on_stat(to_call_context(id), path, true);
		}, s);
}

void sftp_server::handle_rename(const_span s) {
	handle_packet_helper<rename_request>([this](auto& p)
		{
			auto& [id, oldpath, newpath] = p;
			backend_->on_rename(to_call_context(id), oldpath, newpath);
		}, s);
}

void sftp_server::handle_readlink(const_span s) {
	handle_packet_helper<readlink_request>([this](auto& p)
		{
			auto& [id, path] = p;
			backend_->on_readlink(to_call_context(id), path);
		}, s);
}

void sftp_server::handle_symlink(const_span s) {
	handle_packet_helper<symlink_request>([this](auto& p)
		{
			auto& [id, linkpath, targetpath] = p;
			backend_->on_symlink(to_call_context(id), linkpath, targetpath);
		}, s);
}

void sftp_server::handle_extended(const_span s) {
	handle_packet_helper<extended_request>([this](auto& p)
		{
			auto& [id, req] = p;
			backend_->on_extended(to_call_context(id), req, p.reader().rest_of_span());
		}, s);
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

bool sftp_server::send_error(call_context ctx, status_code code, std::string_view message) {
	return send_packet<status_response>(call_id(ctx), code, message, "");
}

bool sftp_server::send_ok(call_context ctx) {
	return send_packet<status_response>(call_id(ctx), status_code::fx_ok, "", "");
}

bool sftp_server::send_open_file(call_context ctx, file_handle_view handle) {
	return send_packet<handle_response>(call_id(ctx), handle);
}

bool sftp_server::send_open_dir(call_context ctx, dir_handle_view handle) {
	return send_packet<handle_response>(call_id(ctx), handle);
}

bool sftp_server::send_read_dir(call_context ctx, std::vector<file_info> const& files) {
	byte_vector p;

	bool res = ser::serialise_to_vector<name_response>(p, call_id(ctx), files.size());

	if(res) {
		ssh_bf_writer res_w(p, p.size());
		for(auto&& v : files) {
			if(!res_w.write(v.filename) ||
				!res_w.write(v.longname) ||
				!v.attrs.write(res_w))
			{
				return false;
			}
		}
	}
	return res;
}

bool sftp_server::send_stat(call_context ctx, file_attributes const& attrs) {
	byte_vector p;

	bool res = ser::serialise_to_vector<attrs_response>(p, call_id(ctx));

	if(res) {
		ssh_bf_writer res_w(p, p.size());
		res = attrs.write(res_w) && send_packet(p);
	}
	return res;
}

bool sftp_server::send_path(call_context ctx, std::string_view path) {
	std::vector<file_info> v{file_info{std::string(path)}};
	return send_read_dir(ctx, v);
}

bool sftp_server::send_extended(call_context ctx, const_span data) {
	byte_vector p;

	bool res = ser::serialise_to_vector<extended_reply_response>(p, call_id(ctx));

	if(res) {
		ssh_bf_writer res_w(p, p.size());
		res = res_w.write(to_string_view(data)) && send_packet(p);
	}
	return res;
}


}
