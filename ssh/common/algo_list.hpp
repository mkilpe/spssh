#ifndef SP_SSH_ALGO_LIST_HEADER
#define SP_SSH_ALGO_LIST_HEADER

#include "util.hpp"
#include "types.hpp"

#include <functional>
#include <memory>
#include <vector>

namespace securepath::ssh {

template<typename Type, typename Impl>
class algo_list {
public:
	using algo_type = Type;
	using ctor = std::function<std::unique_ptr<Impl> (algo_type)>;

	algo_list() = default;
	algo_list(ctor func, std::vector<algo_type> algos)
	: algos_(std::move(algos))
	, function_(std::move(func))
	{
	}

	/// Turn the list of algorithms to ssh name-list
	std::string name_list() const {
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

	/// construct given algorithm
	std::unique_ptr<Impl> construct(algo_type type) const {
		SPSSH_ASSERT(function_, "invalid state");
		return function_(type);
	}

private:
	std::vector<algo_type> algos_;
	std::function<std::unique_ptr<Impl> (algo_type)> function_;
};

}

#endif
