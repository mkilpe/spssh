
#include "test_buffers.hpp"
#include "ssh/core/protocol_helpers.hpp"
#include <external/catch/catch.hpp>

namespace securepath::ssh::test {

TEST_CASE("protocol helpers send_version_string", "[unit]") {
	{
		string_out_buffer out;
		CHECK(send_version_string(ssh_version{"2.0", "testv1.0"}, out));
		CHECK(out.data == "SSH-2.0-testv1.0\r\n");
	}
	{
		string_out_buffer out;
		CHECK(send_version_string(ssh_version{"2.1bb", "kl15dds5@&dtestv1.999", "this is comment äöa"}, out));
		CHECK(out.data == "SSH-2.1bb-kl15dds5@&dtestv1.999 this is comment äöa\r\n");
	}
}


TEST_CASE("protocol helpers parse_ssh_version", "[unit]") {
	{
		string_in_buffer in{"SSH-2.0-testv1.0\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::ok);
		CHECK(v.ssh == "2.0");
		CHECK(v.software == "testv1.0");
		CHECK(v.comment == "");
	}
	{
		string_in_buffer in{"SSH-42.0ab-kl15dds5@&dtestv1.999\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::ok);
		CHECK(v.ssh == "42.0ab");
		CHECK(v.software == "kl15dds5@&dtestv1.999");
		CHECK(v.comment == "");
	}
	{
		string_in_buffer in{"SSH-2.0-testv1.0 this is comment äö\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::ok);
		CHECK(v.ssh == "2.0");
		CHECK(v.software == "testv1.0");
		CHECK(v.comment == "this is comment äö");
	}
	{
		string_in_buffer in{"SSH-2.0-\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::ok);
		CHECK(v.ssh == "2.0");
		CHECK(v.software == "");
		CHECK(v.comment == "");
	}
	{
		string_in_buffer in{"pla pla pla\r\nsome\r\nSSH othersdfj\r\nSSH-2.0-testv1.0\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, true, v) == version_parse_result::ok);
		CHECK(v.ssh == "2.0");
		CHECK(v.software == "testv1.0");
		CHECK(v.comment == "");
	}
	{
		string_in_buffer in{"SSH-testv1.0\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::error);
		CHECK(v.ssh == "");
		CHECK(v.software == "");
		CHECK(v.comment == "");
	}
	{
		string_in_buffer in{"SSH-2-s " + std::string(255-10, 'a') + "\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::ok);
		CHECK(v.ssh == "2");
		CHECK(v.software == "s");
		CHECK(v.comment == std::string(255-10, 'a'));
	}
	{
		// invalid char in ssh version
		string_in_buffer in{"SSH-ö12-testv1.0\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::error);
	}
	{
		// invalid char in software version
		string_in_buffer in{"SSH-12-te\tstv1.0\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::error);
	}
	{
		string_in_buffer in{"SSH-1\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::error);
	}
	{
		// too long
		string_in_buffer in{"SSH-2-s " + std::string(255-9, 'a') + "\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::error);
	}
	{
		string_in_buffer in{""};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::more_data);
	}
	{
		string_in_buffer in{"SSH-1-dd"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::more_data);
	}
	{
		// invalid beginning
		string_in_buffer in{"SSH 1.2-s1\r\n"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::error);
	}
	{
		string_in_buffer in{"SSH-1-dd"};
		ssh_version v;
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::more_data);
		in.data += "\r\n";
		CHECK(parse_ssh_version(in, false, v) == version_parse_result::ok);
		CHECK(v.ssh == "1");
		CHECK(v.software == "dd");
		CHECK(v.comment == "");
	}
}

}