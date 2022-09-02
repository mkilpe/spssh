
#include "file_attributes.hpp"

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

bool file_attributes::read(ssh_bf_reader& r) {
	std::uint32_t flags{};
	bool res = r.read(flags);
	if(res) {
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
	}
	return res;
}

bool file_attributes::write(ssh_bf_writer& w) {
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

}
