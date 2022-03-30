
#include "util.hpp"

namespace securepath::ssh {

char const encoding[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char const pad = '=';

static std::uint8_t char_to_value(char c) {
	if(c == 0x2b) // +
		return 0x3e;

	if(c == 0x2f) // /
		return 0x3f;

	if(c >= 0x30 && c <= 0x39) // 0-9
		return 0x34 + (c - 0x30);

	if(c >= 0x41 && c <= 0x5a) // A-Z
		return c - 0x41;

	if(c >= 0x61 && c <= 0x7a) // a-z
		return 0x1a + (c - 0x61);

	return 0xFF; // invalid
}

std::vector<std::byte> decode_base64(std::string_view s) {
	if(s.empty()) {
		return {};
	}

	std::vector<std::byte> res;
	res.reserve((s.size() / 4) * 3); // 4 chars make 24 bits

	// remove padding and just decode without
	if((s.size() % 4) == 0) {
		if(s.back() == pad) {
			s.remove_suffix(1);
			if(!s.empty() && s.back() == pad) {
				s.remove_suffix(1);
			}
		}
	}

	// handle by four at the time
	for(std::size_t i = 0; i < s.size(); i += 4) {
		auto left = s.size() - i;
		if(left == 1) {
			return {};
		}

		std::uint8_t n1 = char_to_value(s[i]);
		std::uint8_t n2 = char_to_value(s[i+1]);
		if(n1 == 0xFF || n2 == 0xFF) {
			return {};
		}
		res.push_back(std::byte((n1 << 2) | ((n2 & 0x30) >> 4)));

		if(left > 2) {
			std::uint8_t n3 = char_to_value(s[i+2]);
			if(n3 == 0xFF) {
				return {};
			}
			res.push_back(std::byte(((n2 & 0x0f) << 4) | ((n3 & 0x3c) >> 2)));

			if(left > 3) {
				std::uint8_t n4 = char_to_value(s[i+3]);

				if(n4 == 0xFF) {
					return {};
				}

				res.push_back(std::byte(((n3 & 0x03) << 6) | n4));
			}
		}
	}

	return res;
}

}
