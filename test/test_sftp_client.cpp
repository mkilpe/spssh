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

struct client_fixture {
	sftp_record_transport transport{test_log()};
	std::shared_ptr<recording_client_callback> cb = std::make_shared<recording_client_callback>();
	exposed_sftp_client client{cb, transport, channel_side_info{1, 2*1024*1024, 32768}};

	client_fixture() {
		auto& base = static_cast<channel_base&>(client);
		base.on_confirm(channel_side_info{7, 2*1024*1024, 32768}, {});
		base.on_request_success();
		feed(build_packet<version>(3u));
		REQUIRE(cb->last_event() == "version");
		transport.sent.clear();
	}

	void feed(byte_vector const& p) {
		REQUIRE(client.on_data(p));
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
};

bool cb_event(client_fixture& fx, std::string_view name, sftp::call_handle h) {
	return fx.cb->last_event() == name && fx.cb->last_handle() == h;
}

}

TEST_CASE("sftp client subsystem setup", "[unit][sftp]") {
	sftp_record_transport transport(test_log());
	auto cb = std::make_shared<recording_client_callback>();
	exposed_sftp_client client(cb, transport, channel_side_info{1, 2*1024*1024, 32768});
	auto& base = static_cast<channel_base&>(client);

	base.on_confirm(channel_side_info{7, 2*1024*1024, 32768}, {});
	REQUIRE(transport.sent.size() == 1);
	// subsystem request for "sftp"
	CHECK(std::uint8_t(transport.sent[0][0]) == ssh_channel_request);
	ser::channel_subsystem_request::load rp(ser::match_type_t, transport.sent[0]);
	REQUIRE(rp);
	auto& [rid, rtype, rreply, rsubsystem] = rp;
	CHECK(rtype == "subsystem");
	CHECK(rreply == true);
	CHECK(rsubsystem == "sftp");
	transport.sent.clear();

	base.on_request_success();
	auto stream = channel_data_stream(transport.sent);
	auto pkts = parse_sftp_packets(stream);
	REQUIRE(pkts.size() == 1);
	CHECK(pkts[0].type == fxp_init);
	init::load ip(pkts[0].payload);
	REQUIRE(ip);
	auto& [iversion] = ip;
	CHECK(iversion == 3);

	// version with extensions
	auto vp = build_packet<version>(3u);
	ssh_bf_writer w(vp, vp.size());
	REQUIRE(w.write(std::string_view("ext1@test")));
	REQUIRE(w.write(std::string_view("value1")));
	REQUIRE(w.write(std::string_view("ext2@test")));
	REQUIRE(w.write(std::string_view("value2")));
	patch_sftp_length(vp);
	REQUIRE(client.on_data(vp));

	CHECK(cb->last_event() == "version");
	CHECK(cb->version == 3);
	REQUIRE(cb->extensions.size() == 2);
	CHECK(cb->extensions[0].type == "ext1@test");
	CHECK(cb->extensions[0].data == "value1");
	CHECK(cb->extensions[1].type == "ext2@test");
	CHECK(cb->extensions[1].data == "value2");
}

TEST_CASE("sftp client version reject closes channel", "[unit][sftp]") {
	sftp_record_transport transport(test_log());
	auto cb = std::make_shared<recording_client_callback>();
	cb->accept_version = false;
	exposed_sftp_client client(cb, transport, channel_side_info{1, 2*1024*1024, 32768});
	auto& base = static_cast<channel_base&>(client);
	base.on_confirm(channel_side_info{7, 2*1024*1024, 32768}, {});
	base.on_request_success();
	transport.sent.clear();

	REQUIRE(client.on_data(build_packet<version>(3u)));

	bool close_sent = false;
	for(auto&& v : transport.sent) {
		if(!v.empty() && std::uint8_t(v[0]) == ssh_channel_close) {
			close_sent = true;
		}
	}
	CHECK(close_sent);
}

TEST_CASE("sftp client requests emit correct packets", "[unit][sftp]") {
	client_fixture fx;

	SECTION("open_file") {
		file_attributes attrs;
		attrs.permissions = 0600;
		auto h = fx.client.open_file("/file", open_mode(fxf_read|fxf_creat), attrs);
		REQUIRE(h != 0);
		auto pd = fx.sent_one();
		CHECK(pd.type == fxp_open);
		open_request::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, path, mode] = lp;
		CHECK(id == h);
		CHECK(path == "/file");
		CHECK(mode == std::uint32_t(fxf_read|fxf_creat));
		file_attributes in_attrs;
		REQUIRE(in_attrs.read(lp.reader()));
		CHECK(in_attrs.permissions == attrs.permissions);
	}
	SECTION("read_file") {
		auto h = fx.client.read_file("fh", 1234, 4096);
		REQUIRE(h != 0);
		auto pd = fx.sent_one();
		CHECK(pd.type == fxp_read);
		read_request::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, handle, pos, size] = lp;
		CHECK(id == h);
		CHECK(handle == "fh");
		CHECK(pos == 1234);
		CHECK(size == 4096);
	}
	SECTION("write_file") {
		byte_vector data(100, std::byte{'w'});
		auto h = fx.client.write_file("fh", 77, data);
		REQUIRE(h != 0);
		auto pd = fx.sent_one();
		CHECK(pd.type == fxp_write);
		write_request::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, handle, pos, wdata] = lp;
		CHECK(id == h);
		CHECK(handle == "fh");
		CHECK(pos == 77);
		CHECK(wdata == to_string_view(data));
	}
	SECTION("close_file") {
		auto h = fx.client.close_file("fh");
		REQUIRE(h != 0);
		auto pd = fx.sent_one();
		CHECK(pd.type == fxp_close);
	}
	SECTION("stat_file") {
		auto h = fx.client.stat_file("fh");
		REQUIRE(h != 0);
		CHECK(fx.sent_one().type == fxp_fstat);
	}
	SECTION("setstat_file") {
		file_attributes attrs;
		attrs.size = 42;
		auto h = fx.client.setstat_file("fh", attrs);
		REQUIRE(h != 0);
		auto pd = fx.sent_one();
		CHECK(pd.type == fxp_fsetstat);
		fsetstat_request::load lp(pd.payload);
		REQUIRE(lp);
		file_attributes in_attrs;
		REQUIRE(in_attrs.read(lp.reader()));
		CHECK(in_attrs.size == attrs.size);
	}
	SECTION("dir operations") {
		CHECK(fx.client.open_dir("/dir") != 0);
		CHECK(fx.client.read_dir("dh") != 0);
		CHECK(fx.client.close_dir("dh") != 0);
		auto pkts = fx.sent_sftp();
		REQUIRE(pkts.size() == 3);
		CHECK(pkts[0].type == fxp_opendir);
		CHECK(pkts[1].type == fxp_readdir);
		CHECK(pkts[2].type == fxp_close);
	}
	SECTION("path operations") {
		CHECK(fx.client.remove_file("/f") != 0);
		CHECK(fx.client.rename("/a", "/b") != 0);
		CHECK(fx.client.mkdir("/d") != 0);
		CHECK(fx.client.remove_dir("/d") != 0);
		CHECK(fx.client.stat("/f", true) != 0);
		CHECK(fx.client.stat("/f", false) != 0);
		CHECK(fx.client.setstat("/f", {}) != 0);
		CHECK(fx.client.readlink("/l") != 0);
		CHECK(fx.client.symlink("/l", "/t") != 0);
		CHECK(fx.client.realpath(".") != 0);
		auto pkts = fx.sent_sftp();
		REQUIRE(pkts.size() == 10);
		CHECK(pkts[0].type == fxp_remove);
		CHECK(pkts[1].type == fxp_rename);
		CHECK(pkts[2].type == fxp_mkdir);
		CHECK(pkts[3].type == fxp_rmdir);
		CHECK(pkts[4].type == fxp_stat);
		CHECK(pkts[5].type == fxp_lstat);
		CHECK(pkts[6].type == fxp_setstat);
		CHECK(pkts[7].type == fxp_readlink);
		CHECK(pkts[8].type == fxp_symlink);
		CHECK(pkts[9].type == fxp_realpath);
	}
	SECTION("extended") {
		byte_vector data(10, std::byte{'e'});
		auto h = fx.client.extended("test@ext", data);
		REQUIRE(h != 0);
		auto pd = fx.sent_one();
		CHECK(pd.type == fxp_extended);
		extended_request::load lp(pd.payload);
		REQUIRE(lp);
		auto& [id, req] = lp;
		CHECK(id == h);
		CHECK(req == "test@ext");
		// the extension data is appended raw
		auto rest = lp.reader().rest_of_span();
		CHECK(byte_vector(rest.begin(), rest.end()) == data);
	}
}

TEST_CASE("sftp client response dispatch", "[unit][sftp]") {
	client_fixture fx;

	SECTION("open_file -> handle") {
		auto h = fx.client.open_file("/f", fxf_read);
		CHECK(fx.client.pending_calls() == 1);
		fx.feed(build_packet<handle_response>(h, std::string_view("fh1")));
		CHECK(cb_event(fx, "open_file", h));
		CHECK(fx.cb->last_file == "fh1");
		CHECK(fx.client.pending_calls() == 0);
	}
	SECTION("read_file -> data") {
		auto h = fx.client.read_file("fh", 0, 100);
		byte_vector data(100, std::byte{'d'});
		fx.feed(build_packet<data_response>(h, to_string_view(data)));
		CHECK(cb_event(fx, "read_file", h));
		CHECK(fx.cb->last_data == data);
	}
	SECTION("stat_file -> attrs") {
		auto h = fx.client.stat_file("fh");
		file_attributes attrs;
		attrs.size = 12345;
		attrs.permissions = 0100644;
		fx.feed(with_attrs(build_packet<attrs_response>(h), attrs));
		CHECK(cb_event(fx, "stat_file", h));
		CHECK(fx.cb->last_attrs.size == attrs.size);
		CHECK(fx.cb->last_attrs.permissions == attrs.permissions);
	}
	SECTION("stat -> attrs") {
		auto h = fx.client.stat("/f");
		file_attributes attrs;
		attrs.size = 99;
		fx.feed(with_attrs(build_packet<attrs_response>(h), attrs));
		CHECK(cb_event(fx, "stat", h));
		CHECK(fx.cb->last_attrs.size == attrs.size);
	}
	SECTION("open_dir -> handle, read_dir -> names") {
		auto h = fx.client.open_dir("/d");
		fx.feed(build_packet<handle_response>(h, std::string_view("dh1")));
		CHECK(fx.cb->last_dir == "dh1");

		auto h2 = fx.client.read_dir("dh1");
		auto p = build_packet<name_response>(h2, 2u);
		ssh_bf_writer w(p, p.size());
		file_attributes attrs;
		attrs.size = 10;
		REQUIRE(w.write(std::string_view("file1")));
		REQUIRE(w.write(std::string_view("-rw- file1")));
		REQUIRE(attrs.write(w));
		attrs.size = 20;
		REQUIRE(w.write(std::string_view("file2")));
		REQUIRE(w.write(std::string_view("-rw- file2")));
		REQUIRE(attrs.write(w));
		patch_sftp_length(p);
		fx.feed(p);

		CHECK(cb_event(fx, "read_dir", h2));
		REQUIRE(fx.cb->last_files.size() == 2);
		CHECK(fx.cb->last_files[0].filename == "file1");
		CHECK(fx.cb->last_files[0].longname == "-rw- file1");
		CHECK(fx.cb->last_files[0].attrs.size == 10);
		CHECK(fx.cb->last_files[1].filename == "file2");
		CHECK(fx.cb->last_files[1].attrs.size == 20);
	}
	SECTION("readlink and realpath -> single name") {
		auto h = fx.client.readlink("/l");
		auto p = build_packet<name_response>(h, 1u);
		ssh_bf_writer w(p, p.size());
		REQUIRE(w.write(std::string_view("/target")));
		REQUIRE(w.write(std::string_view("")));
		REQUIRE(file_attributes{}.write(w));
		patch_sftp_length(p);
		fx.feed(p);
		CHECK(cb_event(fx, "readlink", h));
		CHECK(fx.cb->last_path == "/target");

		auto h2 = fx.client.realpath(".");
		auto p2 = build_packet<name_response>(h2, 1u);
		ssh_bf_writer w2(p2, p2.size());
		REQUIRE(w2.write(std::string_view("/")));
		REQUIRE(w2.write(std::string_view("")));
		REQUIRE(file_attributes{}.write(w2));
		patch_sftp_length(p2);
		fx.feed(p2);
		CHECK(cb_event(fx, "realpath", h2));
		CHECK(fx.cb->last_path == "/");
	}
	SECTION("status ok dispatch for all status based calls") {
		struct {
			sftp::call_handle h;
			char const* event;
		} const calls[] = {
			{fx.client.write_file("fh", 0, byte_vector(1)), "write_file"},
			{fx.client.close_file("fh"), "close_file"},
			{fx.client.close_dir("dh"), "close_dir"},
			{fx.client.setstat_file("fh", {}), "setstat_file"},
			{fx.client.remove_file("/f"), "remove_file"},
			{fx.client.rename("/a", "/b"), "rename"},
			{fx.client.mkdir("/d"), "mkdir"},
			{fx.client.remove_dir("/d"), "remove_dir"},
			{fx.client.setstat("/f", {}), "setstat"},
			{fx.client.symlink("/l", "/t"), "symlink"},
		};
		for(auto&& c : calls) {
			REQUIRE(c.h != 0);
			fx.feed(build_packet<status_response>(c.h, std::uint32_t(fx_ok), std::string_view(""), std::string_view("")));
			CHECK(cb_event(fx, c.event, c.h));
		}
		CHECK(fx.client.pending_calls() == 0);
	}
	SECTION("extended reply") {
		byte_vector data(5, std::byte{'x'});
		auto h = fx.client.extended("test@ext", data);
		auto p = build_packet<extended_reply_response>(h);
		byte_vector reply_data(7, std::byte{'r'});
		p.insert(p.end(), reply_data.begin(), reply_data.end());
		patch_sftp_length(p);
		fx.feed(p);
		CHECK(cb_event(fx, "extended", h));
		CHECK(fx.cb->last_data == reply_data);
	}
}

TEST_CASE("sftp client failure handling", "[unit][sftp]") {
	client_fixture fx;

	SECTION("error status -> on_failure") {
		auto h = fx.client.open_file("/nope", fxf_read);
		fx.feed(build_packet<status_response>(h, std::uint32_t(fx_no_such_file), std::string_view("no such file"), std::string_view("")));
		CHECK(cb_event(fx, "failure", h));
		CHECK(fx.cb->last_error.code() == fx_no_such_file);
		CHECK(fx.cb->last_error.message() == "no such file");
		CHECK(fx.client.pending_calls() == 0);
	}
	SECTION("eof on read -> on_failure with eof code") {
		auto h = fx.client.read_file("fh", 1000, 100);
		fx.feed(build_packet<status_response>(h, std::uint32_t(fx_eof), std::string_view("End of file"), std::string_view("")));
		CHECK(cb_event(fx, "failure", h));
		CHECK(fx.cb->last_error.code() == fx_eof);
	}
	SECTION("wrong result packet type -> on_failure") {
		auto h = fx.client.open_file("/f", fxf_read);
		fx.feed(build_packet<data_response>(h, std::string_view("data")));
		CHECK(cb_event(fx, "failure", h));
		CHECK(fx.cb->last_error.code() == fx_failure);
		CHECK(fx.client.pending_calls() == 0);
	}
	SECTION("unsolicited response id is ignored") {
		fx.feed(build_packet<handle_response>(424242u, std::string_view("fh")));
		CHECK(fx.cb->events.size() == 1); // just the version event
		CHECK(!fx.transport.disconnected());
	}
	SECTION("malformed response packet disconnects") {
		// status packet with truncated payload
		byte_vector p;
		ssh_bf_writer w(p);
		REQUIRE(w.write(std::uint32_t(5)));
		REQUIRE(w.write(std::uint8_t(fxp_status)));
		REQUIRE(w.write(std::uint32_t(1)));
		REQUIRE(fx.client.on_data(p));
		CHECK(fx.transport.disconnected());
	}
}

}
