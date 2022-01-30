#ifndef SP_SHH_BINARY_FORMAT_HEADER
#define SP_SHH_BINARY_FORMAT_HEADER

#include "types.hpp"
#include "ssh/crypto/random.hpp"

namespace securepath::ssh {

void u32ton(std::uint32_t v, std::byte* out) {
	out[0] = std::byte((v >> 24) & 0xff);
	out[1] = std::byte((v >> 16) & 0xff);
	out[2] = std::byte((v >> 8) & 0xff);
	out[3] = std::byte(v & 0xff);
}

std::uint32_t ntou32(std::byte const* in) {
	return (std::to_integer<std::uint32_t>(in[0]) << 24)
			| (std::to_integer<std::uint32_t>(in[1]) << 16)
			| (std::to_integer<std::uint32_t>(in[2]) << 8)
			| (std::to_integer<std::uint32_t>(in[3]));
}

class ssh_bf_writer {
public:
	ssh_bf_writer(span out)
	: out_(out)
	, pos_()
	{
	}

	span used_span() const {
		return span{out_.data(), pos_};
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

	void add_uint32(std::uint32_t v) {
		SPSSH_ASSERT(size_left() >= 4, "illegal buffer size");
		u32ton(v, out_);
		out += 4;
	}

	void add_uint8(std::uint8_t v) {
		SPSSH_ASSERT(size_left() >= 1, "illegal buffer size");
		out_[pos_] = std::byte{v};
		++pos_;
	}

	void add_string(std::string_view s) {
		SPSSH_ASSERT(size_left() >= s.size(), "illegal buffer size");
		add_uint32(s.size());
		std::memcpy(out_.data()+pos_, s.data(), s.size());
		pos_ += s.size();
	}

	void add_byte_range(span s) {
		SPSSH_ASSERT(size_left() >= s.size(), "illegal buffer size");
		std::memcpy(out_.data()+pos_, s.data(), s.size());
		pos_ += s.size();
	}

	void add_random_range(std::size_t size) {
		SPSSH_ASSERT(size_left() >= size, "illegal buffer size");
		random_bytes(span{out_.data()+pos_, size});
		pos_ += size;
	}

	void jump_over(std::size_t size) {
		SPSSH_ASSERT(size_left() >= size, "illegal buffer size");
		pos_ += size;
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
		return span{in_.data(), pos_};
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

	std::optional<std::uint32_t> extract_uint32() {
		std::optional<std::uint32_t> v;
		if(size_left() >= 4) {
			v = ntou32(in_);
			pos_ += 4;
		}
		return v;
	}

	std::optional<std::uint8_t> extract_uint8() const {
		std::optional<std::uint8_t> v;
		if(size_left() >= 1) {
			v =  std::to_integer<std::uint8_t>(in_[pos_++]);
		}
	}

	std::optional<std::string> extract_string() {
		std::optional<std::string> v;
		auto size = extract_uint32();
		if(size && size_left() >= *size) {
			v = std::string_view{reinterpret_cast<char const*>(in_.data())+pos_, *size};
			pos_ += *size;
		}
		return v;
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
}

#endif
