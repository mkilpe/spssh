#include "configs.hpp"
#include "log.hpp"
#include "util.hpp"
#include "util/server_auth_service.hpp"
#include "util/sftp_fixtures.hpp"

#include "ssh/client/ssh_client.hpp"
#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/service/names.hpp"
#include "ssh/server/ssh_server.hpp"
#include "ssh/services/sftp/local_fs_backend.hpp"
#include "ssh/services/sftp/sftp_session_channel.hpp"
#include "ssh/services/sftp/sftp_transfer.hpp"

#include <external/catch/catch.hpp>

#include <filesystem>
#include <fstream>
#include <random>
#include <algorithm>
#include <iterator>

namespace securepath::ssh::test {
namespace {

using namespace securepath::ssh::sftp;
namespace fs = std::filesystem;

struct temp_dir {
	fs::path path;

	temp_dir() {
		path = fs::temp_directory_path() / ("spssh_sftp_e2e_" + std::to_string(run_id()) + "_" + std::to_string(counter++));
		fs::create_directories(path);
	}

	~temp_dir() {
		std::error_code ec;
		fs::remove_all(path, ec);
	}

	static unsigned run_id() {
		static unsigned const id = std::random_device{}();
		return id;
	}

	inline static int counter{};
};

byte_vector slurp(fs::path const& p) {
	std::ifstream f(p, std::ios::binary);
	std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
	auto sp = to_span(s);
	return byte_vector(sp.begin(), sp.end());
}

void spit(fs::path const& p, std::string_view content) {
	std::ofstream f(p, std::ios::binary);
	f << content;
}

struct sftp_conn_service : ssh_connection {
	sftp_conn_service(transport_base& t, fs::path root)
	: ssh_connection(t)
	{
		add_channel_type("session", [root = std::move(root)](transport_base& tr, channel_side_info info)
		{
			return std::make_unique<sftp_session_channel>(tr, info,
				[&tr, root]()
				{
					return std::make_shared<local_fs_server_backend>(tr.log(), root);
				});
		});
	}
};

struct sftp_test_server : test_context, server_config, ssh_server {
	sftp_test_server(fs::path r)
	: test_context(test_log(), "[server] ")
	, server_config(test_server_config())
	, ssh_server(*this, slog, out_buf)
	, root(std::move(r))
	{
		auth_data.add_password("test-user", "password");
	}

	std::unique_ptr<auth_service> construct_auth() override {
		return std::make_unique<server_test_auth_service>(*this, auth, std::move(auth_data));
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == connection_service_name) {
			return std::make_unique<sftp_conn_service>(*this, root);
		}
		return nullptr;
	}

	fs::path root;
	test_auth_data auth_data;
};

struct sftp_test_client : test_context, client_config, ssh_client {
	sftp_test_client()
	: test_context(test_log(), "[client] ")
	, client_config(test_client_config())
	, ssh_client(*this, slog, out_buf)
	{
		username = "test-user";
		password = "password";
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == connection_service_name) {
			return std::make_unique<ssh_connection>(*this);
		}
		return nullptr;
	}

	ssh_connection& connection() {
		return static_cast<ssh_connection&>(*service_);
	}

	bool open_sftp() {
		auto ch = connection().open_channel("session", [this](transport_base& t, channel_side_info si)
		{
			// the transfer handler sits in front of the recording callback, everything it does not own is forwarded
			transfers = std::make_shared<sftp::sftp_transfer_handler>(cb);
			auto p = std::make_unique<sftp::sftp_client>(transfers, t, si);
			sftp_ = p.get();
			return p;
		});
		if(ch) {
			sftp_channel_id_ = ch->id();
		}
		return ch != nullptr;
	}

	sftp::sftp_client_interface& sftp() { return *sftp_; }
	bool has_channel() { return connection().find_channel(sftp_channel_id_) != nullptr; }

	std::shared_ptr<recording_client_callback> cb = std::make_shared<recording_client_callback>();
	std::shared_ptr<sftp::sftp_transfer_handler> transfers;
	sftp::sftp_client* sftp_{};
	channel_id sftp_channel_id_{};
};

struct e2e {
	temp_dir dir;
	sftp_test_server server{dir.path};
	sftp_test_client client;

	e2e(bool open = true) {
		REQUIRE(run(client, server));
		REQUIRE(client.state() == ssh_state::transport);
		REQUIRE(server.state() == ssh_state::transport);
		if(open) {
			REQUIRE(client.open_sftp());
			REQUIRE(run(client, server));
			REQUIRE(client.cb->last_event() == "version");
			REQUIRE(client.cb->version == 3);
		}
	}

	bool pump() { return run(client, server); }
	recording_client_callback& cb() { return *client.cb; }

	// issue a call, pump and require the expected callback event
	template<typename F>
	void call(F f, std::string_view expected_event) {
		auto h = f();
		REQUIRE(h != 0);
		REQUIRE(pump());
		REQUIRE(cb().last_event() == expected_event);
		REQUIRE(cb().last_handle() == h);
	}
};

}

TEST_CASE("sftp e2e handshake and subsystem start", "[unit][sftp]") {
	e2e t;
	// the fixture already checks the version exchange succeeded
	CHECK(t.client.has_channel());
}

TEST_CASE("sftp e2e file upload and download", "[unit][sftp]") {
	e2e t;

	std::size_t const size = 3*1024*1024 + 333;
	byte_vector data(size);
	for(std::size_t i = 0; i != size; ++i) {
		data[i] = std::byte(i % 251);
	}

	// upload
	t.call([&]{ return t.client.sftp().open_file("/up.bin", open_mode(fxf_write|fxf_creat), {}); }, "open_file");
	auto fh = t.cb().last_file;

	std::size_t const chunk = 32000;
	for(std::size_t pos = 0; pos < size; pos += chunk) {
		auto n = std::min(chunk, size - pos);
		auto h = t.client.sftp().write_file(fh, pos, safe_subspan(data, pos, n));
		REQUIRE(h != 0);
		REQUIRE(t.pump());
		REQUIRE(t.cb().last_event() == "write_file");
	}
	t.call([&]{ return t.client.sftp().close_file(fh); }, "close_file");

	CHECK(slurp(t.dir.path / "up.bin") == data);

	// download
	t.call([&]{ return t.client.sftp().open_file("/up.bin", fxf_read, {}); }, "open_file");
	fh = t.cb().last_file;

	byte_vector rx;
	bool eof = false;
	std::size_t const max_rounds = size/chunk + 10;
	for(std::size_t round = 0; !eof && round < max_rounds; ++round) {
		auto h = t.client.sftp().read_file(fh, rx.size(), chunk);
		REQUIRE(h != 0);
		REQUIRE(t.pump());
		// end of file comes as a read with no data, never as a failure
		REQUIRE(t.cb().last_event() == "read_file");
		eof = t.cb().last_data.empty();
		rx.insert(rx.end(), t.cb().last_data.begin(), t.cb().last_data.end());
	}
	REQUIRE(eof);
	CHECK(rx == data);

	t.call([&]{ return t.client.sftp().close_file(fh); }, "close_file");
}

TEST_CASE("sftp e2e directory operations", "[unit][sftp]") {
	e2e t;

	t.call([&]{ return t.client.sftp().mkdir("/d1"); }, "mkdir");
	CHECK(fs::is_directory(t.dir.path / "d1"));

	spit(t.dir.path / "a.txt", "aaa");
	spit(t.dir.path / "b.txt", "bee");

	t.call([&]{ return t.client.sftp().open_dir("/"); }, "open_dir");
	auto dh = t.cb().last_dir;

	t.call([&]{ return t.client.sftp().read_dir(dh); }, "read_dir");
	REQUIRE(t.cb().last_files.size() == 3);
	bool found_a = false;
	for(auto&& fi : t.cb().last_files) {
		if(fi.filename == "a.txt") {
			found_a = true;
			CHECK(fi.attrs.size == 3);
			CHECK(fi.longname.find("a.txt") != std::string::npos);
		}
	}
	CHECK(found_a);

	// the second read_dir reaches the end of the listing, which is an empty result rather than a failure
	auto h = t.client.sftp().read_dir(dh);
	REQUIRE(h != 0);
	REQUIRE(t.pump());
	REQUIRE(t.cb().last_event() == "read_dir");
	CHECK(t.cb().last_files.empty());

	t.call([&]{ return t.client.sftp().close_dir(dh); }, "close_dir");

	t.call([&]{ return t.client.sftp().rename("/a.txt", "/renamed.txt"); }, "rename");
	CHECK(!fs::exists(t.dir.path / "a.txt"));
	CHECK(fs::exists(t.dir.path / "renamed.txt"));

	t.call([&]{ return t.client.sftp().remove_file("/renamed.txt"); }, "remove_file");
	CHECK(!fs::exists(t.dir.path / "renamed.txt"));

	t.call([&]{ return t.client.sftp().remove_dir("/d1"); }, "remove_dir");
	CHECK(!fs::exists(t.dir.path / "d1"));
}

TEST_CASE("sftp e2e stat and setstat", "[unit][sftp]") {
	e2e t;
	spit(t.dir.path / "f.txt", "0123456789");

	t.call([&]{ return t.client.sftp().stat("/f.txt"); }, "stat");
	CHECK(t.cb().last_attrs.size == 10);
	REQUIRE(t.cb().last_attrs.permissions);
	CHECK((*t.cb().last_attrs.permissions & 0170000) == 0100000);

#ifndef _WIN32
	file_attributes attrs;
	attrs.permissions = 0600;
	t.call([&]{ return t.client.sftp().setstat("/f.txt", attrs); }, "setstat");

	t.call([&]{ return t.client.sftp().stat("/f.txt"); }, "stat");
	CHECK((*t.cb().last_attrs.permissions & 0777) == 0600);
#endif

	// stat and setstat through an open handle
	t.call([&]{ return t.client.sftp().open_file("/f.txt", fxf_read, {}); }, "open_file");
	auto fh = t.cb().last_file;
	t.call([&]{ return t.client.sftp().stat_file(fh); }, "stat_file");
	CHECK(t.cb().last_attrs.size == 10);
	file_attributes fattrs;
	fattrs.size = 5;
	t.call([&]{ return t.client.sftp().setstat_file(fh, fattrs); }, "setstat_file");
	CHECK(fs::file_size(t.dir.path / "f.txt") == 5);
	t.call([&]{ return t.client.sftp().close_file(fh); }, "close_file");
}

TEST_CASE("sftp e2e links and realpath", "[unit][sftp]") {
	e2e t;
	spit(t.dir.path / "target.txt", "data");

#ifndef _WIN32
	t.call([&]{ return t.client.sftp().symlink("/lnk", "target.txt"); }, "symlink");
	CHECK(fs::is_symlink(t.dir.path / "lnk"));

	t.call([&]{ return t.client.sftp().readlink("/lnk"); }, "readlink");
	CHECK(t.cb().last_path == "target.txt");

	// lstat sees the link, stat follows it
	t.call([&]{ return t.client.sftp().stat("/lnk", false); }, "stat");
	CHECK((*t.cb().last_attrs.permissions & 0170000) == 0120000);
	t.call([&]{ return t.client.sftp().stat("/lnk", true); }, "stat");
	CHECK((*t.cb().last_attrs.permissions & 0170000) == 0100000);
#endif

	t.call([&]{ return t.client.sftp().realpath("/x/../target.txt"); }, "realpath");
	CHECK(t.cb().last_path == "/target.txt");
	t.call([&]{ return t.client.sftp().realpath("."); }, "realpath");
	CHECK(t.cb().last_path == "/");
}

TEST_CASE("sftp e2e error paths", "[unit][sftp]") {
	e2e t;

	SECTION("open nonexistent file") {
		auto h = t.client.sftp().open_file("/nope.txt", fxf_read, {});
		REQUIRE(h != 0);
		REQUIRE(t.pump());
		REQUIRE(t.cb().last_event() == "failure");
		CHECK(t.cb().last_error.code() == fx_no_such_file);
	}
	SECTION("path escape is refused") {
		auto h = t.client.sftp().open_file("/../../etc/passwd", fxf_read, {});
		REQUIRE(h != 0);
		REQUIRE(t.pump());
		REQUIRE(t.cb().last_event() == "failure");
		CHECK(t.cb().last_error.code() == fx_permission_denied);
	}
	SECTION("extended request is unsupported") {
		auto h = t.client.sftp().extended("test@ext", {});
		REQUIRE(h != 0);
		REQUIRE(t.pump());
		REQUIRE(t.cb().last_event() == "failure");
		CHECK(t.cb().last_error.code() == fx_op_unsupported);
	}
	SECTION("connection stays usable after errors") {
		auto h = t.client.sftp().open_file("/nope.txt", fxf_read, {});
		REQUIRE(h != 0);
		REQUIRE(t.pump());
		t.call([&]{ return t.client.sftp().mkdir("/works"); }, "mkdir");
		CHECK(fs::is_directory(t.dir.path / "works"));
	}
}

TEST_CASE("sftp e2e close", "[unit][sftp]") {
	e2e t;

	t.call([&]{ return t.client.sftp().mkdir("/d"); }, "mkdir");

	t.client.sftp().close({});
	REQUIRE(t.pump());

	CHECK(!t.client.has_channel());
	CHECK(t.client.state() == ssh_state::transport);
	CHECK(t.server.state() == ssh_state::transport);
}

namespace {

struct bogus_subsystem_channel : channel {
	using channel::channel;

	bool on_confirm(channel_side_info remote, const_span extra) override {
		bool res = channel::on_confirm(remote, extra);
		send_subsystem_request("bogus");
		return res;
	}

	void on_request_success() override { success = true; }
	void on_request_failure() override { failure = true; }

	bool success{};
	bool failure{};
};

}

TEST_CASE("sftp e2e unknown subsystem is refused", "[unit][sftp]") {
	e2e t(false);

	bogus_subsystem_channel* bogus{};
	auto ch = t.client.connection().open_channel("session", [&](transport_base& tr, channel_side_info si)
	{
		auto p = std::make_unique<bogus_subsystem_channel>(tr, si);
		bogus = p.get();
		return p;
	});
	REQUIRE(ch != nullptr);
	REQUIRE(t.pump());

	CHECK(bogus->failure);
	CHECK(!bogus->success);
}

TEST_CASE("sftp e2e version reject closes channel", "[unit][sftp]") {
	e2e t(false);
	t.client.cb->accept_version = false;

	REQUIRE(t.client.open_sftp());
	REQUIRE(t.pump());

	CHECK(t.client.cb->last_event() == "version");
	CHECK(!t.client.has_channel());
	CHECK(t.client.state() == ssh_state::transport);
	CHECK(t.server.state() == ssh_state::transport);
}

// ---- file transfers through sftp_transfer_handler -------------------------------------------------------------

namespace {

byte_vector pattern(std::size_t n) {
	byte_vector v(n);
	for(std::size_t i = 0; i != n; ++i) {
		v[i] = std::byte(i % 251);
	}
	return v;
}

struct transfer_probe {
	bool done{};
	sftp::transfer_result result;
	std::vector<std::uint64_t> progress;

	sftp::transfer_done on_done() {
		return [this](sftp::transfer_id, sftp::transfer_result const& r) { done = true; result = r; };
	}
	sftp::transfer_progress on_progress() {
		return [this](sftp::transfer_id, std::uint64_t bytes) { progress.push_back(bytes); };
	}
};

bool pump_until_done(e2e& t, transfer_probe& p) {
	for(int i = 0; i != 50 && !p.done; ++i) {
		REQUIRE(t.pump());
	}
	return p.done;
}

}

TEST_CASE("sftp transfer upload and download", "[unit][sftp]") {
	e2e t;
	auto data = pattern(1024*1024 + 123);

	transfer_probe up;
	auto id = t.client.transfers->upload(t.client.sftp(), "/up.bin", std::make_unique<sftp::memory_input>(data), {}, up.on_done(), up.on_progress());
	REQUIRE(id != 0);
	REQUIRE(pump_until_done(t, up));
	CHECK(!up.result.error);
	CHECK(!up.result.cancelled);
	CHECK(up.result.bytes == data.size());
	CHECK(slurp(t.dir.path / "up.bin") == data);
	REQUIRE(!up.progress.empty());
	CHECK(std::is_sorted(up.progress.begin(), up.progress.end()));
	CHECK(up.progress.back() == data.size());
	CHECK(t.client.transfers->active_transfers() == 0);

	byte_vector got;
	transfer_probe down;
	id = t.client.transfers->download(t.client.sftp(), "/up.bin", std::make_unique<sftp::memory_output>(got), {}, down.on_done(), down.on_progress());
	REQUIRE(id != 0);
	REQUIRE(pump_until_done(t, down));
	CHECK(!down.result.error);
	CHECK(down.result.bytes == data.size());
	CHECK(got == data);
	REQUIRE(down.result.attrs);
	CHECK(down.result.attrs->size == data.size());
	CHECK(down.progress.back() == data.size());
	CHECK(t.client.transfers->active_transfers() == 0);
}

TEST_CASE("sftp transfer with local files", "[unit][sftp]") {
	e2e t;
	temp_dir local;
	auto data = pattern(300*1024 + 5);
	{
		std::ofstream f(local.path / "in.bin", std::ios::binary);
		f.write(reinterpret_cast<char const*>(data.data()), std::streamsize(data.size()));
	}

	auto in = std::make_unique<sftp::file_input>(local.path / "in.bin");
	REQUIRE(in->is_open());
	CHECK(in->size() == data.size());
	transfer_probe up;
	REQUIRE(t.client.transfers->upload(t.client.sftp(), "/f.bin", std::move(in), {}, up.on_done()) != 0);
	REQUIRE(pump_until_done(t, up));
	CHECK(!up.result.error);
	CHECK(slurp(t.dir.path / "f.bin") == data);

	auto out = std::make_unique<sftp::file_output>(local.path / "out.bin");
	REQUIRE(out->is_open());
	transfer_probe down;
	REQUIRE(t.client.transfers->download(t.client.sftp(), "/f.bin", std::move(out), {}, down.on_done()) != 0);
	REQUIRE(pump_until_done(t, down));
	CHECK(!down.result.error);
	CHECK(slurp(local.path / "out.bin") == data);

	CHECK(!sftp::file_input(local.path / "missing.bin").is_open());
}

TEST_CASE("sftp transfer small chunks and deep pipeline", "[unit][sftp]") {
	e2e t;
	auto data = pattern(100007);
	sftp::transfer_options o;
	o.chunk_size = 1000;
	o.max_in_flight = 8;

	transfer_probe up;
	REQUIRE(t.client.transfers->upload(t.client.sftp(), "/p.bin", std::make_unique<sftp::memory_input>(data), o, up.on_done()) != 0);
	REQUIRE(pump_until_done(t, up));
	CHECK(!up.result.error);
	CHECK(slurp(t.dir.path / "p.bin") == data);

	// without the size known in advance the end is found by reading until eof
	o.stat_first = false;
	byte_vector got;
	transfer_probe down;
	REQUIRE(t.client.transfers->download(t.client.sftp(), "/p.bin", std::make_unique<sftp::memory_output>(got), o, down.on_done()) != 0);
	REQUIRE(pump_until_done(t, down));
	CHECK(!down.result.error);
	CHECK(!down.result.attrs);
	CHECK(got == data);
	CHECK(down.result.bytes == data.size());
}

TEST_CASE("sftp transfer failures", "[unit][sftp]") {
	e2e t;
	spit(t.dir.path / "exists.txt", "x");

	SECTION("download of a missing file") {
		byte_vector got;
		transfer_probe down;
		REQUIRE(t.client.transfers->download(t.client.sftp(), "/missing.bin", std::make_unique<sftp::memory_output>(got), {}, down.on_done()) != 0);
		REQUIRE(pump_until_done(t, down));
		CHECK(down.result.error);
		CHECK(down.result.error.code() == fx_no_such_file);
		CHECK(down.result.bytes == 0);
	}
	SECTION("upload onto a directory") {
		auto data = pattern(10);
		transfer_probe up;
		REQUIRE(t.client.transfers->upload(t.client.sftp(), "/", std::make_unique<sftp::memory_input>(data), {}, up.on_done()) != 0);
		REQUIRE(pump_until_done(t, up));
		CHECK(up.result.error);
	}
	SECTION("exclusive upload onto an existing file") {
		auto data = pattern(10);
		sftp::transfer_options o;
		o.exclusive = true;
		transfer_probe up;
		REQUIRE(t.client.transfers->upload(t.client.sftp(), "/exists.txt", std::make_unique<sftp::memory_input>(data), o, up.on_done()) != 0);
		REQUIRE(pump_until_done(t, up));
		CHECK(up.result.error);
		CHECK(slurp(t.dir.path / "exists.txt") == byte_vector{std::byte('x')});
	}
	CHECK(t.client.transfers->active_transfers() == 0);
	// and the client is still usable, with results the handler does not own reaching the callback behind it
	t.call([&]{ return t.client.sftp().realpath("/"); }, "realpath");
}

TEST_CASE("sftp transfer cancel", "[unit][sftp]") {
	e2e t;
	auto data = pattern(1024*1024);
	{
		std::ofstream f(t.dir.path / "big.bin", std::ios::binary);
		f.write(reinterpret_cast<char const*>(data.data()), std::streamsize(data.size()));
	}

	sftp::transfer_options o;
	o.chunk_size = 4096;
	o.max_in_flight = 2;
	byte_vector got;
	transfer_probe down;
	sftp::transfer_id id{};
	bool cancelled = false;
	id = t.client.transfers->download(t.client.sftp(), "/big.bin", std::make_unique<sftp::memory_output>(got), o, down.on_done()
		, [&](sftp::transfer_id, std::uint64_t bytes) {
			if(bytes >= 20000 && !cancelled) {
				cancelled = true;
				CHECK(t.client.transfers->cancel(id));
			}
		});
	REQUIRE(id != 0);
	REQUIRE(pump_until_done(t, down));
	CHECK(down.result.cancelled);
	CHECK(!down.result.error);
	CHECK(down.result.bytes >= 20000);
	CHECK(down.result.bytes < data.size());
	CHECK(t.client.transfers->active_transfers() == 0);
	CHECK(!t.client.transfers->cancel(id));

	// the stray results of the reads in flight and of the close are dropped, and the session goes on
	t.call([&]{ return t.client.sftp().realpath("/"); }, "realpath");
}

TEST_CASE("sftp transfer handler routes single calls", "[unit][sftp]") {
	e2e t;

	bool mkdir_ok = false;
	REQUIRE(t.client.transfers->call(t.client.sftp().mkdir("/r"), [&](sftp::call_result const& r) {
		mkdir_ok = std::holds_alternative<sftp::mkdir_data>(r);
	}));
	REQUIRE(t.pump());
	CHECK(mkdir_ok);
	CHECK(fs::is_directory(t.dir.path / "r"));

	std::optional<status_code> code;
	REQUIRE(t.client.transfers->call(t.client.sftp().stat("/nope"), [&](sftp::call_result const& r) {
		if(auto e = std::get_if<sftp::sftp_error>(&r)) {
			code = e->code();
		}
	}));
	REQUIRE(t.pump());
	CHECK(code == fx_no_such_file);

	// routed results never reached the callback behind the handler
	CHECK(t.cb().last_event() == "version");
	CHECK(!t.client.transfers->call(0, [](sftp::call_result const&) {}));
}

}
