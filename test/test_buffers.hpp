#ifndef SSH_TEST_BUFFERS_HEADER
#define SSH_TEST_BUFFERS_HEADER

#include "ssh/common/string_buffers.hpp"

#include <cassert>

namespace securepath::ssh::test {

using ssh::string_in_buffer;
using ssh::string_out_buffer;

class string_io_buffer : public in_buffer, public out_buffer {
public:
	string_io_buffer(std::size_t max_size = -1)
	: maximum_size(max_size)
	{}

	span get() override {
		return span{reinterpret_cast<std::byte*>(data.data()), pos};
	}

	void consume(std::size_t size) override {
		assert(size <= data.size());
		assert(size <= pos);
		data = data.substr(size);
		pos -= size;
	}

	span get(std::size_t size) override {
		if(data.size() - pos < size) {
			if(pos+size > maximum_size) {
				return span();
			}
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

	bool empty() const {
		return used_size() == 0;
	}

	std::size_t size() const override {
		return maximum_size-pos;
	}

	std::size_t used_size() const { return pos; }
	std::size_t max_size() const override { return maximum_size; }


	std::size_t const maximum_size;
	std::string data;
	std::size_t pos{};
};


}

#endif