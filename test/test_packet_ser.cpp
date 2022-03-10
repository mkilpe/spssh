
#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/common/packet_ser.hpp"
#include "ssh/common/packet_ser_impl.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::ssh::test {

template<typename PLoad, typename... Args, std::size_t... I>
bool check_tuple(PLoad& t, std::index_sequence<I...>, Args&&... args) {
	return ( (t.template get<I>() == args) && ... );
}

template<typename Packet, typename... Args>
bool test_packet_ser(Args&&... args) {
	std::byte temp[1024] = {};
	typename Packet::save sp(std::forward<Args>(args)...);
	REQUIRE(sp.write(temp));

	typename Packet::load lp(ser::match_type_t, temp);
	REQUIRE(lp);

	return check_tuple(lp, std::make_index_sequence<sizeof...(Args)>(), std::forward<Args>(args)...);
}

TEST_CASE("packet serialisation", "[unit]") {
	CHECK(test_packet_ser<ser::disconnect>(1, "test 1", "test 2"));
	CHECK(test_packet_ser<ser::unimplemented>(25));
	CHECK(test_packet_ser<ser::debug>(true, "test 1", "test 2"));
	CHECK(test_packet_ser<ser::ignore>("test 1"));
}

TEST_CASE("packet serialisation simple", "[unit]") {
	std::byte temp[256] = {};
	ser::disconnect::save sp(1, "test 1", "test 2");
	REQUIRE(sp.write(temp));

	ser::disconnect::load lp(ser::match_type_t, temp);
	REQUIRE(lp);

	auto & [code, m1, m2] = lp;
	CHECK(code == 1);
	CHECK(m1 == "test 1");
	CHECK(m2 == "test 2");
}

TEST_CASE("packet serialisation without typetag", "[unit]") {
	std::byte temp[256] = {};
	ser::disconnect::save sp(1, "test 1", "test 2");
	REQUIRE(sp.write(temp));

	ser::disconnect::load lp(const_span(temp+1, sp.serialised_size()-1));
	REQUIRE(lp);

	auto & [code, m1, m2] = lp;
	CHECK(code == 1);
	CHECK(m1 == "test 1");
	CHECK(m2 == "test 2");
}

TEST_CASE("packet serialisation name-list", "[unit]") {
	std::byte temp[256] = {};
	using test_type = ser::ssh_packet_ser<ssh_disconnect, ser::name_list>;

	test_type::save sp(ser::name_list_t{"test 1", "test 2", "hipshops"});
	REQUIRE(sp.write(temp));

	test_type::load lp(ser::match_type_t, temp);
	REQUIRE(lp);

	auto & [list] = lp;
	CHECK(list == ser::name_list_t{"test 1", "test 2", "hipshops"});
}

TEST_CASE("packet serialisation bytes-n", "[unit]") {
	std::byte temp[256] = {};
	using test_type = ser::ssh_packet_ser<ssh_disconnect, ser::bytes<10>>;

	test_type::save sp(std::span<std::byte const, 10>((std::byte const*)"1234567890", 10));
	REQUIRE(sp.write(temp));

	test_type::load lp(ser::match_type_t, temp);
	REQUIRE(lp);

	auto & [bytes] = lp;
	CHECK(bytes.size() == 10);
	CHECK(std::memcmp(bytes.data(), "1234567890", 10) == 0);
}

}