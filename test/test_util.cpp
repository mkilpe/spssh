
#include "log.hpp"
#include "ssh/common/logger.hpp"
#include "ssh/common/util.hpp"
#include <external/catch/catch.hpp>

namespace securepath::ssh::test {

static byte_vector to_vec(std::string_view s) {
	return byte_vector((std::byte const*)s.data(), (std::byte const*)s.data()+s.size());
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

TEST_CASE("encode_base64", "[unit]") {
	CHECK(encode_base64(to_span("")) == "");
	CHECK(encode_base64(to_span("f")) == "Zg");
	CHECK(encode_base64(to_span("f"), true) == "Zg==");
	CHECK(encode_base64(to_span("fo")) == "Zm8");
	CHECK(encode_base64(to_span("fo"), true) == "Zm8=");
	CHECK(encode_base64(to_span("foo")) == "Zm9v");
	CHECK(encode_base64(to_span("foob")) == "Zm9vYg");
	CHECK(encode_base64(to_span("foob"), true) == "Zm9vYg==");
	CHECK(encode_base64(to_span("fooba")) == "Zm9vYmE");
	CHECK(encode_base64(to_span("fooba"), true) == "Zm9vYmE=");
	CHECK(encode_base64(to_span("foobar")) == "Zm9vYmFy");
}

static byte_vector to_vec(const_span s) {
	return byte_vector(s.begin(), s.end());
}

TEST_CASE("safe_subspan", "[unit]") {

	{
		auto vec = to_vec("test");
		span s = vec;
		CHECK(to_vec(safe_subspan(s, 0)) == to_vec("test"));
		CHECK(to_vec(safe_subspan(s, 1)) == to_vec("est"));
		CHECK(safe_subspan(s, 4).empty());
		CHECK(to_vec(safe_subspan(s, 1, 2)) == to_vec("es"));
		CHECK(to_vec(safe_subspan(s, 2, 6)) == to_vec("st"));
	}

	{
		const_span s = to_span("test");
		CHECK(to_vec(safe_subspan(s, 0)) == to_vec("test"));
		CHECK(to_vec(safe_subspan(s, 1)) == to_vec("est"));
		CHECK(safe_subspan(s, 4).empty());
		CHECK(to_vec(safe_subspan(s, 1, 2)) == to_vec("es"));
		CHECK(to_vec(safe_subspan(s, 2, 6)) == to_vec("st"));
	}

}

}