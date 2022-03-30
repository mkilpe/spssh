
#include "log.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/common/util.hpp"

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::ssh::test {
/*
	BASE64("") = ""
   BASE64("f") = "Zg=="
   BASE64("fo") = "Zm8="
   BASE64("foo") = "Zm9v"
   BASE64("foob") = "Zm9vYg=="
   BASE64("fooba") = "Zm9vYmE="
   BASE64("foobar") = "Zm9vYmFy"*/

static std::vector<std::byte> to_vec(std::string_view s) {
	return std::vector<std::byte>((std::byte const*)s.data(), (std::byte const*)s.data()+s.size());
}

TEST_CASE("decode_base64", "[unit]") {
	CHECK(decode_base64("") == to_vec(""));
	CHECK(decode_base64("Zg") == to_vec("f"));
	CHECK(decode_base64("Zg==") == to_vec("f"));
	CHECK(decode_base64("Zm8") == to_vec("fo"));
	CHECK(decode_base64("Zm8=") == to_vec("fo"));
	CHECK(decode_base64("Zm9v") == to_vec("foo"));
	CHECK(decode_base64("Zm9vYg") == to_vec("foob"));
	CHECK(decode_base64("Zm9vYg==") == to_vec("foob"));
	CHECK(decode_base64("Zm9vYmE") == to_vec("fooba"));
	CHECK(decode_base64("Zm9vYmE=") == to_vec("fooba"));
	CHECK(decode_base64("Zm9vYmFy") == to_vec("foobar"));

	// the low bits are ignored
	CHECK(decode_base64("Zm9vYmF") == to_vec("fooba"));

	CHECK(decode_base64("=").empty());
	CHECK(decode_base64("==").empty());
	CHECK(decode_base64("-").empty());
	CHECK(decode_base64("G").empty());
	CHECK(decode_base64("G===").empty());
	CHECK(decode_base64("Zm9vYgfdd").empty());
}


}