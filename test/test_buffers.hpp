#ifndef SSH_TEST_BUFFERS_HEADER
#define SSH_TEST_BUFFERS_HEADER

#include "ssh/common/buffers.hpp"

#include <cassert>

namespace securepath::ssh::test {

class string_in_buffer : public in_buffer {
public:
	string_in_buffer(std::string s) : data(s) {}

	const_span get() const override {
		return const_span{reinterpret_cast<std::byte const*>(data.data()+consumed), data.size()-consumed};
	}

	void consume(std::size_t size) override {
		assert(size <= data.size()-consumed);
		consumed += size;
	}

	std::string data;
	std::size_t consumed{};
};


class string_out_buffer : public out_buffer {
public:
	span get(std::size_t size) override {
		if(data.size() - used < size) {
			data.resize(used + size);
		}
		return span{reinterpret_cast<std::byte*>(data.data()+used), data.size()-used};
	}

	span expand(std::size_t new_size, std::size_t) override {
		return get(new_size);
	}

	void commit(std::size_t size) override {
		assert(size <= data.size()-used);
		used += size;
	}

	std::size_t max_size() const override { return -1; }

	std::string data;
	std::size_t used{};
};


class string_io_buffer : public in_buffer, public out_buffer {
public:
	const_span get() const override {
		return const_span{reinterpret_cast<std::byte const*>(data.data()), pos};
	}

	void consume(std::size_t size) override {
		assert(size <= data.size());
		assert(size <= pos);
		data = data.substr(size);
		pos -= size;
	}

	span get(std::size_t size) override {
		if(data.size() - pos < size) {
			data.resize(pos+size);
		}
		return span{reinterpret_cast<std::byte*>(data.data()+pos), data.size()-pos};
	}

	span expand(std::size_t new_size, std::size_t) override {
		return get(new_size);
	}

	void commit(std::size_t size) override {
		assert(size <= data.size()-pos);
		pos += size;
	}

	std::size_t max_size() const override { return -1; }

	std::string data;
	std::size_t pos{};
};


}

#endif