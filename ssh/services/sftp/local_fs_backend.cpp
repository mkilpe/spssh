#include "local_fs_backend.hpp"

#include <algorithm>
#include <cerrno>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace securepath::ssh::sftp {

namespace fs = std::filesystem;

std::optional<resolved_path> confine_path(fs::path const& root, std::string_view client_path) {
	fs::path rel = fs::path(client_path).relative_path().lexically_normal();
	if(rel == ".") {
		rel = fs::path();
	}
	if(!rel.empty() && rel.filename().empty()) {
		// normalisation can leave a trailing separator (e.g. "d/." becomes "d/"), drop it
		rel = rel.parent_path();
	}
	if(!rel.empty() && *rel.begin() == "..") {
		return std::nullopt;
	}
	std::error_code ec;
	fs::path croot = fs::canonical(root, ec);
	if(ec) {
		return std::nullopt;
	}
	// appending an empty path would add a trailing separator
	fs::path full = rel.empty() ? croot : croot / rel;
	// resolve symlinks to make sure the path stays inside the root
	fs::path resolved = fs::weakly_canonical(full, ec);
	if(ec) {
		return std::nullopt;
	}
	auto mm = std::mismatch(croot.begin(), croot.end(), resolved.begin(), resolved.end());
	if(mm.first != croot.end()) {
		return std::nullopt;
	}
	return resolved_path{std::move(full), std::move(rel)};
}

status_code to_status_code(std::error_code const& ec) {
	status_code res = fx_failure;
	if(ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory) {
		res = fx_no_such_file;
	} else if(ec == std::errc::permission_denied || ec == std::errc::operation_not_permitted) {
		res = fx_permission_denied;
	}
	return res;
}

std::string to_virtual_path(fs::path const& rel) {
	return "/" + rel.generic_string();
}

static bool read_attributes(fs::path const& p, bool follow_symlinks, file_attributes& out, std::error_code& ec) {
	struct ::stat st{};
	int res = follow_symlinks ? ::stat(p.c_str(), &st) : ::lstat(p.c_str(), &st);
	if(res != 0) {
		ec = std::error_code(errno, std::generic_category());
		return false;
	}
	out.size = std::uint64_t(st.st_size);
	out.uid = std::uint32_t(st.st_uid);
	out.gid = std::uint32_t(st.st_gid);
	out.permissions = std::uint32_t(st.st_mode);
	out.atime = std::uint32_t(st.st_atime);
	out.mtime = std::uint32_t(st.st_mtime);
	return true;
}

static std::ios::openmode to_openmode(open_mode mode) {
	std::ios::openmode m = std::ios::binary;
	if(mode & fxf_read) {
		m |= std::ios::in;
	}
	if(mode & fxf_write) {
		m |= std::ios::out;
	}
	if(mode & fxf_append) {
		m |= std::ios::app;
	}
	if(mode & fxf_trunc) {
		m |= std::ios::trunc;
	}
	return m;
}

local_fs_server_backend::local_fs_server_backend(logger& l, fs::path root)
: sftp_server_backend(l)
, root_(std::move(root))
{
}

std::optional<resolved_path> local_fs_server_backend::resolve(call_context ctx, std::string_view path) {
	SPSSH_ASSERT(s_, "invalid state");
	auto res = confine_path(root_, path);
	if(!res) {
		log_.log(logger::debug, "sftp path refused [path={}]", path);
		s_->send_error(ctx, fx_permission_denied, "Path not allowed");
	}
	return res;
}

bool local_fs_server_backend::send_errc(call_context ctx, std::error_code const& ec) {
	return s_->send_error(ctx, to_status_code(ec), ec.message());
}

local_fs_server_backend::file_entry* local_fs_server_backend::find_file(call_context ctx, file_handle_view handle) {
	SPSSH_ASSERT(s_, "invalid state");
	auto it = files_.find(handle);
	file_entry* res{};
	if(it != files_.end()) {
		res = &it->second;
	} else {
		s_->send_error(ctx, fx_failure, "Invalid file handle");
	}
	return res;
}

local_fs_server_backend::dir_entry* local_fs_server_backend::find_dir(call_context ctx, dir_handle_view handle) {
	SPSSH_ASSERT(s_, "invalid state");
	auto it = dirs_.find(handle);
	dir_entry* res{};
	if(it != dirs_.end()) {
		res = &it->second;
	} else {
		s_->send_error(ctx, fx_failure, "Invalid directory handle");
	}
	return res;
}

void local_fs_server_backend::on_open_file(call_context ctx, std::string_view path, open_mode mode, file_attributes attrs) {
	if(auto rp = resolve(ctx, path)) {
		open_resolved_file(ctx, *rp, mode, attrs);
	}
}

void local_fs_server_backend::open_resolved_file(call_context ctx, resolved_path const& rp, open_mode mode, file_attributes const& attrs) {
	std::error_code ec;
	bool exists = fs::exists(rp.full, ec);
	if((mode & fxf_excl) && exists) {
		s_->send_error(ctx, fx_failure, "File already exists");
	} else if(!(mode & fxf_creat) && !exists) {
		s_->send_error(ctx, fx_no_such_file, "No such file");
	} else {
		if(!exists) {
			// touch the file first, fstream does not create it when opened for both reading and writing
			std::ofstream touch(rp.full, std::ios::binary);
		}
		file_entry entry{};
		entry.stream.open(rp.full, to_openmode(mode));
		if(entry.stream.is_open()) {
			if(!exists && attrs.permissions) {
				fs::permissions(rp.full, fs::perms(*attrs.permissions & 07777), ec);
			}
			entry.path = rp.full;
			std::string handle = "f" + std::to_string(++handle_counter_);
			files_.emplace(handle, std::move(entry));
			s_->send_open_file(ctx, handle);
		} else {
			s_->send_error(ctx, fx_failure, "Failed to open file");
		}
	}
}

void local_fs_server_backend::on_close_file(call_context ctx, file_handle_view handle) {
	if(auto* entry = find_file(ctx, handle)) {
		entry->stream.close();
		files_.erase(files_.find(handle));
		s_->send_ok(ctx);
	}
}

void local_fs_server_backend::on_read_file(call_context ctx, file_handle_view handle, std::uint64_t pos, std::uint32_t size) {
	if(auto* entry = find_file(ctx, handle)) {
		auto& f = entry->stream;
		f.clear();
		f.seekg(std::streamoff(pos));
		std::uint32_t count = std::min(size, max_read_size);
		byte_vector buf(count);
		f.read(reinterpret_cast<char*>(buf.data()), std::streamsize(count));
		std::streamsize got = f.gcount();
		if(got > 0 || count == 0) {
			s_->send_read_file(ctx, const_span(buf.data(), std::size_t(got)));
		} else if(f.eof()) {
			s_->send_error(ctx, fx_eof, "End of file");
		} else {
			s_->send_error(ctx, fx_failure, "Failed to read file");
		}
	}
}

void local_fs_server_backend::on_write_file(call_context ctx, file_handle_view handle, std::uint64_t pos, const_span data) {
	if(auto* entry = find_file(ctx, handle)) {
		auto& f = entry->stream;
		f.clear();
		// note: in append mode the write position is ignored and data is appended
		f.seekp(std::streamoff(pos));
		f.write(reinterpret_cast<char const*>(data.data()), std::streamsize(data.size()));
		f.flush();
		if(f.good()) {
			s_->send_ok(ctx);
		} else {
			s_->send_error(ctx, fx_failure, "Failed to write file");
		}
	}
}

void local_fs_server_backend::on_stat_file(call_context ctx, file_handle_view handle) {
	if(auto* entry = find_file(ctx, handle)) {
		std::error_code ec;
		file_attributes attrs;
		if(read_attributes(entry->path, true, attrs, ec)) {
			s_->send_stat(ctx, attrs);
		} else {
			send_errc(ctx, ec);
		}
	}
}

void local_fs_server_backend::on_setstat_file(call_context ctx, file_handle_view handle, file_attributes attrs) {
	if(auto* entry = find_file(ctx, handle)) {
		std::error_code ec;
		if(apply_attributes(entry->path, attrs, ec)) {
			s_->send_ok(ctx);
		} else {
			send_errc(ctx, ec);
		}
	}
}

bool local_fs_server_backend::apply_attributes(fs::path const& p, file_attributes const& attrs, std::error_code& ec) {
	if(attrs.size) {
		fs::resize_file(p, *attrs.size, ec);
	}
	if(!ec && attrs.permissions) {
		fs::permissions(p, fs::perms(*attrs.permissions & 07777), ec);
	}
	if(!ec && attrs.uid && attrs.gid) {
		if(::chown(p.c_str(), *attrs.uid, *attrs.gid) != 0) {
			ec = std::error_code(errno, std::generic_category());
		}
	}
	if(!ec && attrs.atime && attrs.mtime) {
		timespec times[2] = {{std::time_t(*attrs.atime), 0}, {std::time_t(*attrs.mtime), 0}};
		if(::utimensat(AT_FDCWD, p.c_str(), times, 0) != 0) {
			ec = std::error_code(errno, std::generic_category());
		}
	}
	return !ec;
}

void local_fs_server_backend::on_open_dir(call_context ctx, std::string_view path) {
	if(auto rp = resolve(ctx, path)) {
		std::error_code ec;
		fs::directory_iterator it(rp->full, ec);
		if(ec) {
			send_errc(ctx, ec);
		} else {
			std::string handle = "d" + std::to_string(++handle_counter_);
			dirs_.emplace(handle, dir_entry{std::move(it)});
			s_->send_open_dir(ctx, handle);
		}
	}
}

void local_fs_server_backend::on_read_dir(call_context ctx, dir_handle_view handle) {
	if(auto* entry = find_dir(ctx, handle)) {
		std::vector<file_info> files;
		std::error_code ec;
		auto& it = entry->it;
		while(!ec && it != fs::directory_iterator() && files.size() < max_read_dir_count) {
			file_info fi;
			fi.filename = it->path().filename().generic_string();
			std::error_code sec; // per entry stat failures give just empty attributes
			read_attributes(it->path(), false, fi.attrs, sec);
			fi.longname = to_longname(fi.attrs, fi.filename);
			files.push_back(std::move(fi));
			it.increment(ec);
		}
		if(ec) {
			send_errc(ctx, ec);
		} else if(files.empty()) {
			s_->send_error(ctx, fx_eof, "End of directory");
		} else {
			s_->send_read_dir(ctx, files);
		}
	}
}

void local_fs_server_backend::on_close_dir(call_context ctx, dir_handle_view handle) {
	if(find_dir(ctx, handle)) {
		dirs_.erase(dirs_.find(handle));
		s_->send_ok(ctx);
	}
}

void local_fs_server_backend::on_remove_file(call_context ctx, std::string_view path) {
	if(auto rp = resolve(ctx, path)) {
		std::error_code ec;
		auto st = fs::symlink_status(rp->full, ec);
		if(ec) {
			send_errc(ctx, ec);
		} else if(fs::is_directory(st)) {
			s_->send_error(ctx, fx_failure, "Cannot remove a directory");
		} else if(fs::remove(rp->full, ec)) {
			s_->send_ok(ctx);
		} else if(ec) {
			send_errc(ctx, ec);
		} else {
			s_->send_error(ctx, fx_no_such_file, "No such file");
		}
	}
}

void local_fs_server_backend::on_rename(call_context ctx, std::string_view old_path, std::string_view new_path) {
	if(auto rp_old = resolve(ctx, old_path)) {
		if(auto rp_new = resolve(ctx, new_path)) {
			std::error_code ec;
			auto st = fs::symlink_status(rp_new->full, ec);
			if(st.type() != fs::file_type::not_found) {
				// the version 3 protocol requires rename to fail if the target exists
				s_->send_error(ctx, fx_failure, "Target already exists");
			} else {
				fs::rename(rp_old->full, rp_new->full, ec);
				if(ec) {
					send_errc(ctx, ec);
				} else {
					s_->send_ok(ctx);
				}
			}
		}
	}
}

void local_fs_server_backend::on_mkdir(call_context ctx, std::string_view path, file_attributes attrs) {
	if(auto rp = resolve(ctx, path)) {
		std::error_code ec;
		if(fs::create_directory(rp->full, ec) && !ec) {
			if(attrs.permissions) {
				fs::permissions(rp->full, fs::perms(*attrs.permissions & 07777), ec);
			}
			s_->send_ok(ctx);
		} else if(ec) {
			send_errc(ctx, ec);
		} else {
			s_->send_error(ctx, fx_failure, "Directory already exists");
		}
	}
}

void local_fs_server_backend::on_remove_dir(call_context ctx, std::string_view path) {
	if(auto rp = resolve(ctx, path)) {
		std::error_code ec;
		auto st = fs::symlink_status(rp->full, ec);
		if(ec) {
			send_errc(ctx, ec);
		} else if(!fs::is_directory(st)) {
			s_->send_error(ctx, fx_no_such_file, "Not a directory");
		} else if(fs::remove(rp->full, ec) && !ec) {
			s_->send_ok(ctx);
		} else if(ec) {
			send_errc(ctx, ec);
		} else {
			s_->send_error(ctx, fx_failure, "Failed to remove directory");
		}
	}
}

void local_fs_server_backend::on_stat(call_context ctx, std::string_view path, bool follow_symlinks) {
	if(auto rp = resolve(ctx, path)) {
		std::error_code ec;
		file_attributes attrs;
		if(read_attributes(rp->full, follow_symlinks, attrs, ec)) {
			s_->send_stat(ctx, attrs);
		} else {
			send_errc(ctx, ec);
		}
	}
}

void local_fs_server_backend::on_setstat(call_context ctx, std::string_view path, file_attributes attrs) {
	if(auto rp = resolve(ctx, path)) {
		std::error_code ec;
		if(apply_attributes(rp->full, attrs, ec)) {
			s_->send_ok(ctx);
		} else {
			send_errc(ctx, ec);
		}
	}
}

void local_fs_server_backend::on_readlink(call_context ctx, std::string_view path) {
	if(auto rp = resolve(ctx, path)) {
		std::error_code ec;
		fs::path target = fs::read_symlink(rp->full, ec);
		if(ec) {
			send_errc(ctx, ec);
		} else {
			// the target is returned as it was stored when the link was created
			s_->send_path(ctx, target.generic_string());
		}
	}
}

void local_fs_server_backend::on_symlink(call_context ctx, std::string_view link, std::string_view path) {
	if(auto rp = resolve(ctx, link)) {
		std::error_code ec;
		// the target is stored as given, escaping the root through the link is refused on later access
		fs::create_symlink(fs::path(std::string(path)), rp->full, ec);
		if(ec) {
			send_errc(ctx, ec);
		} else {
			s_->send_ok(ctx);
		}
	}
}

void local_fs_server_backend::on_realpath(call_context ctx, std::string_view path) {
	if(auto rp = resolve(ctx, path)) {
		s_->send_path(ctx, to_virtual_path(rp->rel));
	}
}

void local_fs_server_backend::on_extended(call_context ctx, std::string_view ext_request, const_span) {
	SPSSH_ASSERT(s_, "invalid state");
	log_.log(logger::debug, "sftp extended request not supported [request={}]", ext_request);
	s_->send_error(ctx, fx_op_unsupported, "Extensions not supported");
}

}
