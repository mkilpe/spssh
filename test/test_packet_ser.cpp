
#include "test_buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/core/packet_ser.hpp"
#include "ssh/core/packet_ser_impl.hpp"
#include "ssh/services/sftp/packet_ser.hpp"
#include "ssh/services/sftp/packet_ser_impl.hpp"
#include "ssh/core/protocol.hpp"
#include <external/catch/catch.hpp>

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

struct test_span : std::span<std::byte const, 16> {
	using span::span;
};

bool operator==(std::span<std::byte const, 16> const& l, test_span const& r) {
	return std::memcmp(l.data(), r.data(), 16) == 0;
}

TEST_CASE("packet serialisation", "[unit]") {
	CHECK(test_packet_ser<ser::disconnect>(1u, "test 1", "test 2"));
	CHECK(test_packet_ser<ser::unimplemented>(25u));
	CHECK(test_packet_ser<ser::debug>(true, "test 1", "test 2"));
	CHECK(test_packet_ser<ser::ignore>("test 1"));
	CHECK(test_packet_ser<ser::kexinit>(
		test_span((std::byte const*)"1234567890123456", 16),
			std::vector<std::string_view>{"1", "2", "3"},
			std::vector<std::string_view>{"4", "5"},
			std::vector<std::string_view>{},
			std::vector<std::string_view>{"6", "7", "8"},
			std::vector<std::string_view>{"9"},
			std::vector<std::string_view>{"10", "11", "12", "13"},
			std::vector<std::string_view>{"14", "15"},
			std::vector<std::string_view>{},
			std::vector<std::string_view>{"16", "17", "18"},
			std::vector<std::string_view>{"19"},
			true,
			1u
		));
}

TEST_CASE("packet serialisation simple", "[unit]") {
	std::byte temp[256] = {};
	ser::disconnect::save sp(1, "test 1", "test 2");
	CHECK(sp.size() == 1+4+4+6+4+6);
	REQUIRE(sp.write(temp));
	CHECK(sp.serialised_size() == sp.size());

	ser::disconnect::load lp(ser::match_type_t, temp);
	CHECK(sp.size() == lp.size());
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

using outer = ser::ssh_packet_ser
<
	1,
	ser::boolean,
	ser::string,
	ser::string
>;

using inner = ser::ssh_packet_ser
<
	2,
	ser::uint32,
	ser::string
>;


TEST_CASE("nested packet save", "[unit]") {
	std::byte temp[1024] = {};

	inner::save inner_p{9, "my test"};
	auto outer_p = make_packet_saver<outer>(true, inner_p, "some");
	CHECK(outer_p.write(temp));

	outer::load outer_l(ser::match_type_t, temp);
	REQUIRE(outer_l);

	auto & [b, inner_p_string, str] = outer_l;
	CHECK(b == true);
	CHECK(str == "some");

	inner::load inner_l(ser::match_type_t, to_span(inner_p_string));
	REQUIRE(inner_l);

	auto & [n, inner_str] = inner_l;
	CHECK(n == 9);
	CHECK(inner_str == "my test");
}


using sftp_test = sftp::sftp_packet_ser
<
	3,
	ser::uint32,
	ser::string
>;

TEST_CASE("sftp packet serialisation", "[unit]") {
	std::byte temp[256] = {};

	sftp_test::save sp(32, "my test string");
	CHECK(sp.size() == 4+1+4+4+14);
	REQUIRE(sp.write(temp));

	sftp_test::load lp(ser::match_type_t, temp);
	REQUIRE(lp);

	auto & [num, str] = lp;
	CHECK(num == 32);
	CHECK(str == "my test string");
}

TEST_CASE("nested packet save with sftp", "[unit]") {
	std::byte temp[1024] = {};

	sftp_test::save inner_p{9, "my test"};
	auto outer_p = make_packet_saver<outer>(true, inner_p, "some");
	CHECK(outer_p.write(temp));

	outer::load outer_l(ser::match_type_t, temp);
	REQUIRE(outer_l);

	auto & [b, inner_p_string, str] = outer_l;
	CHECK(b == true);
	CHECK(str == "some");

	sftp_test::load inner_l(ser::match_type_t, to_span(inner_p_string));
	REQUIRE(inner_l);

	auto & [n, inner_str] = inner_l;
	CHECK(n == 9);
	CHECK(inner_str == "my test");
}

}