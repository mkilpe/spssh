#ifndef SSH_COMMON_STRING_BUFFERS_HEADER
#define SSH_COMMON_STRING_BUFFERS_HEADER

#include "buffers.hpp"

#include <cassert>

namespace securepath::ssh {

class string_in_buffer : public in_buffer {
public:
	string_in_buffer(std::string s = {}) : data(s) {}

	span get() override {
		return span{reinterpret_cast<std::byte*>(data.data()) + pos, data.size() - pos};
	}

	void consume(std::size_t size) override {
		assert(size <= data.size() - pos);
		// advance a read offset instead of reallocating, so the span from get() stays valid across
		// partial consumes as the in_buffer contract promises; only a full consume may invalidate it
		pos += size;
		if(pos == data.size()) {
			data.clear();
			pos = 0;
		}
	}

	void add(std::string_view s) {
		// reclaim the consumed prefix before growing; add() is not consume() so it may move the data
		if(pos != 0) {
			data.erase(0, pos);
			pos = 0;
		}
		data.insert(data.end(), s.begin(), s.end());
	}

	std::size_t size() const {
		return data.size() - pos;
	}

	std::string data;
	std::size_t pos{};
};


class string_out_buffer : public out_buffer {
public:
	string_out_buffer(std::size_t max_size = -1)
	: maximum_size(max_size)
	{}

	span get(std::size_t size) override {
		if(data.size() - used < size) {
			if(used+size > maximum_size) {
				return span();
			}
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

	std::size_t size() const override { return maximum_size - used; }
	std::size_t max_size() const override { return maximum_size; }

	bool empty() const { return used == 0; }

	std::string extract_committed() {
		auto s = data.substr(0, used);
		used = 0;
		return s;
	}

	std::size_t const maximum_size;
	std::string data;
	std::size_t used{};
};

}

#endif