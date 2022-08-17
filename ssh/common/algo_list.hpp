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
	algo_list(std::initializer_list<algo_type> list)
	: algos_(list)
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

	void clear() {
		algos_.clear();
	}

	bool empty() const {
		return algos_.empty();
	}

	algo_type front() const {
		SPSSH_ASSERT(!empty(), "invalid state");
		return algos_.front();
	}

	algo_type preferred() const {
		return front();
	}

	bool supports(algo_type t) const {
		for(auto&& v : algos_) {
			if(v == t) return true;
		}
		return false;
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

	std::vector<algo_type>::const_iterator begin() const { return algos_.begin(); }
	std::vector<algo_type>::const_iterator end() const { return algos_.end(); }

private:
	std::vector<algo_type> algos_;
};

template<typename Tag> struct type_tag {};

template<typename Type>
algo_list<Type> algo_list_from_string_list(std::vector<std::string_view> const& list) {
	algo_list<Type> ret;
	for(auto&& v : list) {
		ret.add_back(from_string(type_tag<Type>{}, v));
	}
	return ret;
}

}

#endif
