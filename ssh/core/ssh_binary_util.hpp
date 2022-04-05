#ifndef SP_SHH_BINARY_FORMAT_HEADER
#define SP_SHH_BINARY_FORMAT_HEADER

#include "util.hpp"
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
	{
	}

	ssh_bf_writer(byte_vector& out)
	: buffer_(&out)
	, out_(out)
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

	bool adjust_size(std::size_t s) {
		bool ret = size_left() >= s;
		if(!ret && buffer_) {
			buffer_->resize(buffer_->size()+s);
			out_ = span(*buffer_);
			ret = true;
		}
		return ret;
	}

	bool write(std::uint32_t v) {
		bool ret = adjust_size(4);
		if(ret) {
			u32ton(v, out_.data()+pos_);
			pos_ += 4;
		}
		return ret;
	}

	bool write(std::uint8_t v) {
		bool ret = adjust_size(1);
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
		bool ret = adjust_size(4+v.size());
		if(ret) {
			write(std::uint32_t(v.size()));
			std::memcpy(out_.data()+pos_, v.data(), v.size());
			pos_ += v.size();
		}
		return ret;
	}

	template<std::size_t S>
	bool write(std::span<std::byte const, S> const& s) {
		bool ret = adjust_size(s.size());
		if(ret) {
			std::memcpy(out_.data()+pos_, s.data(), s.size());
			pos_ += s.size();
		}
		return ret;
	}

	bool add_random_range(random& gen, std::size_t size) {
		bool ret = adjust_size(size);
		if(ret) {
			gen.random_bytes(span{out_.data()+pos_, size});
			pos_ += size;
		}
		return ret;
	}

	bool jump_over(std::size_t size) {
		bool ret = adjust_size(size);
		if(ret) {
			pos_ += size;
		}
		return ret;
	}

private:
	byte_vector* buffer_{};
	span out_;
	std::size_t pos_{};
};

class ssh_bf_binout_writer {
public:
	ssh_bf_binout_writer(binout& out)
	: out_(out)
	{}

	bool write(std::uint32_t v) {
		std::byte arr[4];
		u32ton(v, arr);
		return out_.process(arr);
	}

	bool write(std::uint8_t v) {
		std::byte var{v};
		return out_.process(const_span(&var, 1));
	}

	bool write(bool v) {
		return write(std::uint8_t{v});
	}

	bool write(std::string_view v) {
		return write(to_span(v));
	}

	bool write(const_span s) {
		return write(std::uint32_t(s.size()))
			&& out_.process(s);
	}

	bool write(const_mpint_span mpint) {
		const_span d = mpint.data;
		// remove the trailing zeroes
		while(!d.empty() && d[0] == std::byte{0x0}) {
			d = d.subspan(1);
		}
		bool ret = false;
		// write size and add required zero if most significant bit is set
		if(!d.empty() && (std::to_integer<std::uint8_t>(d[0]) & 0x80)) {
			ret = write(std::uint32_t(d.size()+1))
				&& write(std::uint8_t{0x0});
		} else {
			ret = write(std::uint32_t(d.size()));
		}
		return ret && out_.process(d);
	}

	template<std::size_t S>
	bool write(std::span<std::byte const, S> const& s) {
		return out_.process(const_span(s.data(), s.size()));
	}

private:
	binout& out_;
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
