
#include "file_attributes.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace securepath::ssh::sftp {

attribute_flags file_attributes::flags() const {
	std::uint32_t f{};
	if(size) {
		f |= size_attribute;
	}
	if(uid && gid) {
		f |= uidgid_attribute;
	}
	if(permissions) {
		f |= permissions_attribute;
	}
	if(atime && mtime) {
		f |= acmodtime_attribute;
	}
	if(!extended.empty()) {
		f |= extended_attribute;
	}
	return attribute_flags(f);
}

template<typename Type>
static void read_value(bool& res, ssh_bf_reader& r, std::optional<Type>& v) {
	if(res) {
		Type t{};
		res = r.read(t);
		if(res) {
			v = t;
		}
	}
}

bool file_attributes::read(ssh_bf_reader& r, std::uint32_t flags) {
	bool res = true;
	if(flags & size_attribute) {
		read_value(res, r, size);
	}
	if(flags & uidgid_attribute) {
		read_value(res, r, uid);
		read_value(res, r, gid);
	}
	if(flags & permissions_attribute) {
		read_value(res, r, permissions);
	}
	if(flags & acmodtime_attribute) {
		read_value(res, r, atime);
		read_value(res, r, mtime);
	}
	if(flags & extended_attribute) {
		std::uint32_t count{};
		res = r.read(count);
		for(std::uint32_t i = 0; res && i != count; ++i) {
			ext_data_view d;
			res = r.read(d.type) && r.read(d.data);
			if(res) {
				extended.push_back(ext_data{std::string(d.type), std::string(d.data)});
			}
		}
	}
	return res;
}

bool file_attributes::read(ssh_bf_reader& r) {
	std::uint32_t flags{};
	return r.read(flags) && read(r, flags);
}

bool file_attributes::write(ssh_bf_writer& w) const {
	std::uint32_t f = flags();
	bool res = w.write(f);
	if(res && size) {
		res = w.write(*size);
	}
	if(res && uid && gid) {
		res = w.write(*uid) && w.write(*gid);
	}
	if(res && permissions) {
		res = w.write(*permissions);
	}
	if(res && atime && mtime) {
		res = w.write(*atime) && w.write(*mtime);
	}
	if(res) {
		if(!extended.empty()) {
			res = w.write(std::uint32_t(extended.size()));
		}
		for(auto const& v : extended) {
			if(res) {
				res = w.write(v.type) && w.write(v.data);
			}
		}
	}
	return res;
}

static char type_char(std::uint32_t mode) {
	char res = '-';
	std::uint32_t const type_mask = 0170000;
	if((mode & type_mask) == 0040000) {
		res = 'd';
	} else if((mode & type_mask) == 0120000) {
		res = 'l';
	}
	return res;
}

static std::string mode_string(std::uint32_t mode) {
	std::string_view const rwx = "rwxrwxrwx";
	std::string res(rwx.size(), '-');
	for(std::size_t i = 0; i != rwx.size(); ++i) {
		if(mode & (std::uint32_t(1) << (rwx.size() - 1 - i))) {
			res[i] = rwx[i];
		}
	}
	return res;
}

std::string to_longname(file_attributes const& a, std::string_view filename) {
	std::uint32_t mode = a.permissions ? *a.permissions : 0;
	std::time_t mtime = a.mtime ? std::time_t(*a.mtime) : 0;
	char time_buf[32] = {};
#ifndef _WIN32
	char const* const time_format = "%b %e %H:%M";
#else
	// the windows runtime does not support %e
	char const* const time_format = "%b %d %H:%M";
#endif
	std::strftime(time_buf, sizeof(time_buf), time_format, std::gmtime(&mtime));

	std::ostringstream out;
	out << type_char(mode) << mode_string(mode)
		<< " " << std::setw(3) << 1 // link count, not tracked
		<< " " << std::setw(8) << (a.uid ? *a.uid : 0)
		<< " " << std::setw(8) << (a.gid ? *a.gid : 0)
		<< " " << std::setw(10) << (a.size ? *a.size : 0)
		<< " " << time_buf
		<< " " << filename;
	return out.str();
}

std::string to_string(file_attributes const& a) {
	bool first = true;
	std::ostringstream out;
	out << "{";
	if(a.size) {
		out << "size=" << *a.size;
		first = false;
	}
	if(a.uid && a.gid) {
		out << (first ? "" : ", ") << "uid=" << *a.uid << ", gid=" << *a.gid;
		first = false;
	}
	if(a.permissions) {
		out << (first ? "" : ", ") << "perm=" << std::oct << *a.permissions;
		first = false;
	}
	if(a.atime && a.mtime) {
		std::time_t atime = *a.atime;
		std::time_t mtime = *a.mtime;

		out << (first ? "" : ", ") << "atime=" << std::put_time(std::gmtime(&atime), "%c") << ", "
									<< "mtime=" << std::put_time(std::gmtime(&mtime), "%c");
		first = false;
	}
	if(!a.extended.empty()) {
		out << (first ? "" : ", ") << "[";
		bool first_v = true;
		for(auto v : a.extended) {
			if(!first_v) {
				out << ", ";
			}
			first_v = false;
			out << v.type << "=" << to_hex(to_span(v.data));
		}
		out << "]";
	}
	out << "}";
	return out.str();
}

}
