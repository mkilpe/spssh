#ifndef SP_SHH_BINARY_FORMAT_HEADER
#define SP_SHH_BINARY_FORMAT_HEADER

#include "ssh/common/types.hpp"
#include "ssh/common/util.hpp"
#include "ssh/crypto/random.hpp"

#include <cstring>
#include <optional>

namespace securepath::ssh {

class ssh_bf_writer {
public:
	ssh_bf_writer(span out)
	: out_(out)
	, pos_()
	{
	}

	span used_span() const {
		return out_.subspan(0, pos_);
	}

	span total_span() const {
		return out_;
	}

	std::size_t used_size() const {
		return pos_;
	}

	std::size_t size_left() const {
		return out_.size() - pos_;
	}

	bool write(std::uint32_t v) {
		bool ret = size_left() >= 4;
		if(ret) {
			u32ton(v, out_.data()+pos_);
			pos_ += 4;
		}
		return ret;
	}

	bool write(std::uint8_t v) {
		bool ret = size_left() >= 1;
		if(ret) {
			out_[pos_] = std::byte{v};
			++pos_;
		}
		return ret;
	}

	bool write(bool v) {
		return write(std::uint8_t{v});
	}

	bool write(std::string_view v) {
		bool ret = size_left() >= 4+v.size();
		if(ret) {
			write(std::uint32_t(v.size()));
			std::memcpy(out_.data()+pos_, v.data(), v.size());
			pos_ += v.size();
		}
		return ret;
	}

	template<std::size_t S>
	bool write(std::span<std::byte const, S> const& s) {
		bool ret = size_left() >= s.size();
		if(ret) {
			std::memcpy(out_.data()+pos_, s.data(), s.size());
			pos_ += s.size();
		}
		return ret;
	}

	bool add_random_range(random& gen, std::size_t size) {
		bool ret = size_left() >= size;
		if(ret) {
			gen.random_bytes(span{out_.data()+pos_, size});
			pos_ += size;
		}
		return ret;
	}

	bool jump_over(std::size_t size) {
		bool ret = size_left() >= size;
		if(ret) {
			pos_ += size;
		}
		return ret;
	}

private:
	span out_;
	std::size_t pos_;
};

class ssh_bf_reader {
public:
	ssh_bf_reader(const_span in)
	: in_(in)
	, pos_()
	{
	}

	const_span used_span() const {
		return in_.subspan(0, pos_);
	}

	const_span total_span() const {
		return in_;
	}

	std::size_t used_size() const {
		return pos_;
	}

	std::size_t size_left() const {
		return in_.size() - pos_;
	}

	bool read(std::uint32_t& v) {
		bool ret = size_left() >= 4;
		if(ret) {
			v = ntou32(in_.data() + pos_);
			pos_ += 4;
		}
		return ret;
	}

	bool read(std::uint8_t& v) {
		bool ret = size_left() >= 1;
		if(ret) {
			v = std::to_integer<std::uint8_t>(in_[pos_++]);
		}
		return ret;
	}

	bool read(bool& v) {
		bool ret = size_left() >= 1;
		if(ret) {
			v = std::to_integer<std::uint8_t>(in_[pos_++]) != 0;
		}
		return ret;
	}

	bool read(std::string_view& v) {
		std::uint32_t size;
		bool ret = read(size) && size_left() >= size;
		if(ret) {
			v = std::string_view{reinterpret_cast<char const*>(in_.data())+pos_, size};
			pos_ += size;
		}
		return ret;
	}

	template<std::size_t S>
	bool read(std::optional<std::span<std::byte const, S>>& s) {
		bool ret = size_left() >= S;
		if(ret) {
			s = std::span<std::byte const, S>(in_.data()+pos_, S);
			pos_ += S;
		}
		return ret;
	}

	bool jump_over(std::size_t size) {
		bool res = size_left() >= size;
		if(res) {
			pos_ += size;
		}
		return res;
	}

private:
	const_span in_;
	std::size_t pos_;
};

}

#endif
