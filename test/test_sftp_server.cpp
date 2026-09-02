#include "log.hpp"
#include "util/sftp_fixtures.hpp"

#include "ssh/services/sftp/packet_ser_impl.hpp"
#include "ssh/services/sftp/protocol.hpp"

#include <external/catch/catch.hpp>

namespace securepath::ssh::test {
namespace {

using namespace securepath::ssh::sftp;

template<typename Packet, typename... Args>
byte_vector build_packet(Args&&... args) {
	byte_vector p;
	REQUIRE(ser::serialise_to_vector<Packet>(p, std::forward<Args>(args)...));
	return p;
}

byte_vector with_attrs(byte_vector p, file_attributes const& attrs) {
	ssh_bf_writer w(p, p.size());
	REQUIRE(attrs.write(w));
	patch_sftp_length(p);
	return p;
}

struct server_fixture {
	sftp_record_transport transport{test_log()};
	std::shared_ptr<recording_server_backend> backend = std::make_shared<recording_server_backend>(test_log());
	exposed_sftp_server server{make_established_channel(transport), backend};

	server_fixture() {
		transport.sent.clear(); // drop the channel open confirmation
	}

	void feed(byte_vector const& p) {
		REQUIRE(server.on_data(p));
	}

	std::vector<sftp_packet_data> sent_sftp() {
		auto res = parse_sftp_packets(channel_data_stream(transport.sent));
		transport.sent.clear();
		return res;
	}

	sftp_packet_data sent_one() {
		auto pkts = sent_sftp();
		REQUIRE(pkts.size() == 1);
		return pkts.front();
	}

	void check_status(std::uint32_t id, status_code code) {
		auto pd = sent_one();
		REQUIRE(pd.type == fxp_status);
		status_response::load lp(pd.payload);
		REQUIRE(lp);
		auto& [rid, rcode, msg, lang] = lp;
		CHECK(rid == id);
		CHECK(rcode == std::uint32_t(code));
	}
};

}

TEST_CASE("sftp server version negotiation", "[unit][sftp]") {
	server_fixture fx;

	SECTION("same version") {
		fx.feed(build_packet<init>(3u));
		CHECK(fx.backend->last_event() == "init");
		CHECK(fx.backend->init_version == 3);
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_version);
		version::load lp(pd.payload);
		REQUIRE(lp);
		auto& [v] = lp;
		CHECK(v == 3);
	}
	SECTION("newer client version is negotiated down") {
		fx.feed(build_packet<init>(99u));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_version);
		version::load lp(pd.payload);
		REQUIRE(lp);
		auto& [v] = lp;
		CHECK(v == 3);
	}
	SECTION("init with extensions") {
		auto p = build_packet<init>(3u);
		ssh_bf_writer w(p, p.size());
		REQUIRE(w.write(std::string_view("ext@test")));
		REQUIRE(w.write(std::string_view("1")));
		patch_sftp_length(p);
		fx.feed(p);
		REQUIRE(fx.backend->extensions.size() == 1);
		CHECK(fx.backend->extensions[0].type == "ext@test");
		CHECK(fx.backend->extensions[0].data == "1");
	}
}

TEST_CASE("sftp server request dispatch", "[unit][sftp]") {
	server_fixture fx;

	SECTION("open with attrs") {
		file_attributes attrs;
		attrs.permissions = 0640;
		fx.feed(with_attrs(build_packet<open_request>(7u, std::string_view("/f"), std::uint32_t(fxf_write|fxf_creat)), attrs));
		CHECK(fx.backend->last_event() == "open_file");
		CHECK(fx.backend->last_ctx() == 7);
		CHECK(fx.backend->last_path == "/f");
		CHECK(fx.backend->last_mode == std::uint32_t(fxf_write|fxf_creat));
		CHECK(fx.backend->last_attrs.permissions == attrs.permissions);
	}
	SECTION("read") {
		fx.feed(build_packet<read_request>(8u, std::string_view("fh"), std::uint64_t(1234), 4096u));
		CHECK(fx.backend->last_event() == "read_file");
		CHECK(fx.backend->last_handle == "fh");
		CHECK(fx.backend->last_pos == 1234);
		CHECK(fx.backend->last_size == 4096);
	}
	SECTION("write") {
		byte_vector data(10, std::byte{'w'});
		fx.feed(build_packet<write_request>(9u, std::string_view("fh"), std::uint64_t(55), to_string_view(data)));
		CHECK(fx.backend->last_event() == "write_file");
		CHECK(fx.backend->last_pos == 55);
		CHECK(fx.backend->last_data == data);
	}
	SECTION("stat variants") {
		fx.feed(build_packet<stat_request>(1u, std::string_view("/f")));
		CHECK(fx.backend->last_event() == "stat");
		CHECK(fx.backend->last_follow == true);
		fx.feed(build_packet<lstat_request>(2u, std::string_view("/f")));
		CHECK(fx.backend->last_event() == "stat");
		CHECK(fx.backend->last_follow == false);
		fx.feed(build_packet<fstat_request>(3u, std::string_view("fh")));
		CHECK(fx.backend->last_event() == "stat_file");
		CHECK(fx.backend->last_handle == "fh");
	}
	SECTION("setstat goes to path version, fsetstat to handle version") {
		file_attributes attrs;
		attrs.size = 42;
		fx.feed(with_attrs(build_packet<setstat_request>(1u, std::string_view("/f")), attrs));
		CHECK(fx.backend->last_event() == "setstat");
		CHECK(fx.backend->last_path == "/f");
		CHECK(fx.backend->last_attrs.size == attrs.size);

		fx.feed(with_attrs(build_packet<fsetstat_request>(2u, std::string_view("fh")), attrs));
		CHECK(fx.backend->last_event() == "setstat_file");
		CHECK(fx.backend->last_handle == "fh");
	}
	SECTION("dir and path requests") {
		fx.feed(build_packet<opendir_request>(1u, std::string_view("/d")));
		CHECK(fx.backend->last_event() == "open_dir");
		fx.feed(build_packet<readdir_request>(2u, std::string_view("dh")));
		CHECK(fx.backend->last_event() == "read_dir");
		fx.feed(build_packet<remove_request>(3u, std::string_view("/f")));
		CHECK(fx.backend->last_event() == "remove_file");
		fx.feed(build_packet<rename_request>(4u, std::string_view("/a"), std::string_view("/b")));
		CHECK(fx.backend->last_event() == "rename");
		CHECK(fx.backend->last_path == "/a");
		CHECK(fx.backend->last_target == "/b");
		fx.feed(with_attrs(build_packet<mkdir_request>(5u, std::string_view("/d")), {}));
		CHECK(fx.backend->last_event() == "mkdir");
		fx.feed(build_packet<rmdir_request>(6u, std::string_view("/d")));
		CHECK(fx.backend->last_event() == "remove_dir");
		fx.feed(build_packet<readlink_request>(7u, std::string_view("/l")));
		CHECK(fx.backend->last_event() == "readlink");
		fx.feed(build_packet<symlink_request>(8u, std::string_view("/l"), std::string_view("/t")));
		CHECK(fx.backend->last_event() == "symlink");
		CHECK(fx.backend->last_path == "/l");
		CHECK(fx.backend->last_target == "/t");
		fx.feed(build_packet<realpath_request>(9u, std::string_view(".")));
		CHECK(fx.backend->last_event() == "realpath");
	}
	SECTION("extended with raw data") {
		auto p = build_packet<extended_request>(1u, std::string_view("test@ext"));
		byte_vector data(6, std::byte{'e'});
		p.insert(p.end(), data.begin(), data.end());
		patch_sftp_length(p);
		fx.feed(p);
		CHECK(fx.backend->last_event() == "extended");
		CHECK(fx.backend->last_ext_request == "test@ext");
		CHECK(fx.backend->last_data == data);
	}
}

TEST_CASE("sftp server close routing", "[unit][sftp]") {
	server_fixture fx;

	// issue a directory handle so the server records it
	REQUIRE(fx.server.send_open_dir(1, "dh1"));
	fx.transport.sent.clear();

	fx.feed(build_packet<close_request>(2u, std::string_view("dh1")));
	CHECK(fx.backend->last_event() == "close_dir");
	CHECK(fx.backend->last_handle == "dh1");

	fx.feed(build_packet<close_request>(3u, std::string_view("fh1")));
	CHECK(fx.backend->last_event() == "close_file");
	CHECK(fx.backend->last_handle == "fh1");

	// the dir handle was removed on close, so closing again routes to file
	fx.feed(build_packet<close_request>(4u, std::string_view("dh1")));
	CHECK(fx.backend->last_event() == "close_file");
}

TEST_CASE("sftp server responses", "[unit][sftp]") {
	server_fixture fx;

	SECTION("send_ok and send_error") {
		REQUIRE(fx.server.send_ok(5));
		fx.check_status(5, fx_ok);

		REQUIRE(fx.server.send_error(6, fx_permission_denied, "not allowed"));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_status);
		status_response::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, code, msg, lang] = lp;
		CHECK(id == 6);
		CHECK(code == std::uint32_t(fx_permission_denied));
		CHECK(msg == "not allowed");
	}
	SECTION("send_open_file and send_open_dir") {
		REQUIRE(fx.server.send_open_file(1, "fh"));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_handle);
		handle_response::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, handle] = lp;
		CHECK(id == 1);
		CHECK(handle == "fh");

		REQUIRE(fx.server.send_open_dir(2, "dh"));
		CHECK(fx.sent_one().type == fxp_handle);
	}
	SECTION("send_read_file") {
		byte_vector data(100, std::byte{'r'});
		REQUIRE(fx.server.send_read_file(3, data));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_data);
		data_response::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, rdata] = lp;
		CHECK(id == 3);
		CHECK(rdata == to_string_view(data));
	}
	SECTION("send_stat") {
		file_attributes attrs;
		attrs.size = 4242;
		attrs.permissions = 0100600;
		REQUIRE(fx.server.send_stat(4, attrs));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_attrs);
		attrs_response::load lp(pd.payload);
		REQUIRE(lp);
		file_attributes out;
		REQUIRE(out.read(lp.reader()));
		CHECK(out.size == attrs.size);
		CHECK(out.permissions == attrs.permissions);
	}
	SECTION("send_read_dir") {
		std::vector<file_info> files;
		file_attributes attrs;
		attrs.size = 10;
		files.push_back(file_info{"a.txt", "-rw- a.txt", attrs});
		attrs.size = 20;
		files.push_back(file_info{"b.txt", "-rw- b.txt", attrs});

		REQUIRE(fx.server.send_read_dir(5, files));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_name);
		name_response::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, count] = lp;
		CHECK(id == 5);
		REQUIRE(count == 2);
		auto& r = lp.reader();
		std::string_view name, longname;
		file_attributes out;
		REQUIRE(r.read(name));
		REQUIRE(r.read(longname));
		REQUIRE(out.read(r));
		CHECK(name == "a.txt");
		CHECK(longname == "-rw- a.txt");
		CHECK(out.size == 10);
		REQUIRE(r.read(name));
		REQUIRE(r.read(longname));
		REQUIRE(out.read(r));
		CHECK(name == "b.txt");
		CHECK(out.size == 20);
	}
	SECTION("send_path") {
		REQUIRE(fx.server.send_path(6, "/some/path"));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_name);
		name_response::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, count] = lp;
		CHECK(count == 1);
		std::string_view name;
		REQUIRE(lp.reader().read(name));
		CHECK(name == "/some/path");
	}
	SECTION("send_extended") {
		byte_vector data(8, std::byte{'x'});
		REQUIRE(fx.server.send_extended(7, data));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_extended_reply);
		extended_reply_response::load lp(pd.payload);
		REQUIRE(lp);
		auto rest = lp.reader().rest_of_span();
		CHECK(byte_vector(rest.begin(), rest.end()) == data);
	}
	SECTION("send_version with extensions") {
		std::vector<ext_data_view> ext{{"ext@one", "1"}, {"ext@two", "2"}};
		REQUIRE(fx.server.send_version(3, ext));
		auto pd = fx.sent_one();
		REQUIRE(pd.type == fxp_version);
		version::load lp(pd.payload);
		REQUIRE(lp);
		auto& r = lp.reader();
		std::string_view t, d;
		REQUIRE(r.read(t));
		REQUIRE(r.read(d));
		CHECK(t == "ext@one");
		CHECK(d == "1");
		REQUIRE(r.read(t));
		REQUIRE(r.read(d));
		CHECK(t == "ext@two");
		CHECK(d == "2");
	}
}

TEST_CASE("sftp server unsupported and malformed packets", "[unit][sftp]") {
	server_fixture fx;

	SECTION("unknown request type gets op unsupported status") {
		byte_vector p;
		ssh_bf_writer w(p);
		REQUIRE(w.write(std::uint32_t(5))); // length
		REQUIRE(w.write(std::uint8_t(21))); // unassigned type
		REQUIRE(w.write(std::uint32_t(77))); // request id
		fx.feed(p);
		CHECK(!fx.transport.disconnected());
		fx.check_status(77, fx_op_unsupported);
	}
	SECTION("unknown request without id is ignored") {
		byte_vector p;
		ssh_bf_writer w(p);
		REQUIRE(w.write(std::uint32_t(1)));
		REQUIRE(w.write(std::uint8_t(21)));
		fx.feed(p);
		CHECK(!fx.transport.disconnected());
		CHECK(fx.sent_sftp().empty());
	}
	SECTION("truncated request disconnects") {
		byte_vector p;
		ssh_bf_writer w(p);
		REQUIRE(w.write(std::uint32_t(5)));
		REQUIRE(w.write(std::uint8_t(fxp_open)));
		REQUIRE(w.write(std::uint32_t(1))); // only the id, no filename or flags
		fx.feed(p);
		CHECK(fx.transport.disconnected());
	}
	SECTION("open without attributes disconnects") {
		// attrs are mandatory in the open packet
		fx.feed(build_packet<open_request>(1u, std::string_view("/f"), std::uint32_t(fxf_read)));
		CHECK(fx.transport.disconnected());
	}
}

TEST_CASE("sftp server closes channel on eof", "[unit][sftp]") {
	server_fixture fx;

	static_cast<channel_base&>(fx.server).on_eof();

	bool close_sent = false;
	for(auto&& v : fx.transport.sent) {
		if(!v.empty() && std::uint8_t(v[0]) == ssh_channel_close) {
			close_sent = true;
		}
	}
	CHECK(close_sent);
}

}
