#ifndef SP_SSH_ALGO_LIST_HEADER
#define SP_SSH_ALGO_LIST_HEADER

#include "util.hpp"
#include "types.hpp"

#include <algorithm>
#include <functional>
#include <memory>
#include <vector>

namespace securepath::ssh {

template<typename Type>
class algo_list {
public:
	using algo_type = Type;

	algo_list() = default;
	algo_list(std::vector<algo_type> algos)
	: algos_(std::move(algos))
	{
	}

	void add_back(algo_type t) {
		for(auto&& v : algos_) {
			if(v == t) return;
		}
		algos_.push_back(t);
	}

	void add_front(algo_type t) {
		for(auto&& v : algos_) {
			if(v == t) return;
		}
		algos_.insert(algos_.begin(), t);
	}

	void remove(algo_type t) {
		auto it = std::find(algos_.begin(), algos_.end(), t);
		if(it != algos_.end()) {
			algos_.erase(it);
		}
	}

	bool empty() const {
		return algos_.empty();
	}

	algo_type front() const {
		SPSSH_ASSERT(!empty(), "invalid state");
		return algos_.front();
	}

	/// Turn the list of algorithms to ssh name-list
	std::vector<std::string_view> name_list() const {
		std::vector<std::string_view> res;
		res.reserve(algos_.size());
		for(auto&& v : algos_) {
			res.push_back(to_string(v));
		}
		return res;
	}

	/// Turn the list of algorithms to ssh name-list string
	std::string name_list_string() const {
		std::string res;
		bool first = true;
		for(auto&& v : algos_) {
			if(!first) {
				res += ",";
			}
			first = false;
			res += to_string(v);
		}
		return res;
	}

private:
	std::vector<algo_type> algos_;
};

}

#endif
