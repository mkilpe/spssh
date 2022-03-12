
#include "log.hpp"
#include "ssh/common/algo_list.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::ssh::test {
namespace {
enum class test_algos {
	test1,
	test2,
	test3
};

std::string_view to_string(test_algos t) {
	using enum test_algos;
	if(t == test1) return "test1";
	if(t == test2) return "test2";
	if(t == test3) return "test3";
	return "unknown";
}

struct test_base {
	test_base(test_algos t) : type(t) {}
	test_algos type;
};

std::unique_ptr<test_base> test_ctor(test_algos t) {
	return std::make_unique<test_base>(t);
}
}

TEST_CASE("algo_list", "[unit]") {
	using enum test_algos;
	{
		algo_list<test_algos, test_base> list;
		CHECK(list.name_list() == "");
	}
	{
		algo_list<test_algos, test_base> list(test_ctor, {test1,test2,test3});
		CHECK(list.name_list() == "test1,test2,test3");
		CHECK(list.construct(test2)->type == test2);
	}
	{
		algo_list<test_algos, test_base> list(test_ctor, {test3,test1});
		CHECK(list.name_list() == "test3,test1");
	}
}

}