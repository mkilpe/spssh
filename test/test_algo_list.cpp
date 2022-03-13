
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

}

TEST_CASE("algo_list", "[unit]") {
	using enum test_algos;
	{
		algo_list<test_algos> list;
		CHECK(list.name_list().empty());
		CHECK(list.name_list_string() == "");

		list.add_back(test1);
		CHECK(list.name_list_string() == "test1");
		list.add_back(test2);
		CHECK(list.name_list_string() == "test1,test2");
		list.add_front(test3);
		CHECK(list.name_list_string() == "test3,test1,test2");
		list.remove(test1);
		CHECK(list.name_list_string() == "test3,test2");

		CHECK(list.front() == test3);
	}
	{
		algo_list<test_algos> list({test1,test2,test3});
		CHECK(list.name_list() == std::vector<std::string_view>({"test1", "test2", "test3"}));
		CHECK(list.name_list_string() == "test1,test2,test3");
	}
	{
		algo_list<test_algos> list({test3,test1});
		CHECK(list.name_list() == std::vector<std::string_view>({"test3", "test1"}));
		CHECK(list.name_list_string() == "test3,test1");
	}
}

}