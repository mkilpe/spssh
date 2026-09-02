#include "log.hpp"
#include "util/sftp_fixtures.hpp"

#include "ssh/services/sftp/local_fs_backend.hpp"

#include <external/catch/catch.hpp>

#include <filesystem>
#include <fstream>
#include <random>
#include <iterator>

namespace securepath::ssh::test {
namespace {

using namespace securepath::ssh::sftp;
namespace fs = std::filesystem;

struct temp_dir {
	fs::path path;

	temp_dir() {
		path = fs::temp_directory_path() / ("spssh_sftp_test_" + std::to_string(run_id()) + "_" + std::to_string(counter++));
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

/// records the results the backend sends
struct recording_interface : sftp_server_interface {
	void close(std::string_view) override { last = "close"; }
	bool send_version(std::uint32_t, std::vector<ext_data_view> const&) override { last = "version"; return true; }
	bool send_error(sftp::call_context, status_code c, std::string_view m) override {
		last = "error";
		code = c;
		message = m;
		return true;
	}
	bool send_ok(sftp::call_context) override { last = "ok"; return true; }
	bool send_open_file(sftp::call_context, file_handle_view h) override {
		last = "open_file";
		handle = h;
		return true;
	}
	bool send_read_file(sftp::call_context, const_span d) override {
		last = "data";
		data.assign(d.begin(), d.end());
		return true;
	}
	bool send_open_dir(sftp::call_context, dir_handle_view h) override {
		last = "open_dir";
		handle = h;
		return true;
	}
	bool send_read_dir(sftp::call_context, std::vector<file_info> const& f) override {
		last = "read_dir";
		files = f;
		return true;
	}
	bool send_stat(sftp::call_context, file_attributes const& a) override {
		last = "stat";
		attrs = a;
		return true;
	}
	bool send_path(sftp::call_context, std::string_view p) override {
		last = "path";
		path = std::string(p);
		return true;
	}
	bool send_extended(sftp::call_context, const_span) override { last = "extended"; return true; }

	std::string last;
	status_code code{};
	std::string message;
	std::string handle;
	byte_vector data;
	std::vector<file_info> files;
	file_attributes attrs;
	std::string path;
};

struct backend_fixture {
	temp_dir dir;
	recording_interface iface;
	local_fs_server_backend backend{test_log(), dir.path};

	backend_fixture() {
		backend.attach(&iface);
	}

	~backend_fixture() {
		backend.detach();
	}

	void make_file(std::string const& name, std::string const& content = "content") {
		std::ofstream f(dir.path / name, std::ios::binary);
		f << content;
	}

	std::string open_for(std::string const& path, std::uint32_t mode) {
		backend.on_open_file(1, path, open_mode(mode), {});
		REQUIRE(iface.last == "open_file");
		return iface.handle;
	}

	const_span to_data(std::string const& s) {
		data_ = s;
		return const_span(reinterpret_cast<std::byte const*>(data_.data()), data_.size());
	}

private:
	std::string data_;
};

}

TEST_CASE("sftp confine_path", "[unit][sftp]") {
	temp_dir dir;
	fs::create_directories(dir.path / "sub");
	auto croot = fs::canonical(dir.path);

	CHECK(confine_path(dir.path, "/")->full == croot);
	CHECK(confine_path(dir.path, ".")->full == croot);
	CHECK(confine_path(dir.path, "")->full == croot);
	CHECK(confine_path(dir.path, "/sub")->full == croot / "sub");
	CHECK(confine_path(dir.path, "sub")->rel == fs::path("sub"));
	CHECK(confine_path(dir.path, "a/../b")->rel == fs::path("b"));
	CHECK(confine_path(dir.path, "/x/y/../../sub")->rel == fs::path("sub"));

	CHECK(!confine_path(dir.path, ".."));
	CHECK(!confine_path(dir.path, "/.."));
	CHECK(!confine_path(dir.path, "/../etc/passwd"));
	CHECK(!confine_path(dir.path, "a/../../b"));

#ifndef _WIN32
	// symlink pointing outside the root is refused
	fs::create_symlink("/etc", dir.path / "escape");
	CHECK(!confine_path(dir.path, "/escape"));
	CHECK(!confine_path(dir.path, "/escape/passwd"));

	// symlink pointing inside the root is fine
	fs::create_symlink("sub", dir.path / "good");
	CHECK(confine_path(dir.path, "/good"));
#endif

	// nonexistent root fails
	CHECK(!confine_path(dir.path / "nonexistent", "/"));
}

TEST_CASE("sftp to_status_code", "[unit][sftp]") {
	CHECK(to_status_code(std::make_error_code(std::errc::no_such_file_or_directory)) == fx_no_such_file);
	CHECK(to_status_code(std::make_error_code(std::errc::not_a_directory)) == fx_no_such_file);
	CHECK(to_status_code(std::make_error_code(std::errc::permission_denied)) == fx_permission_denied);
	CHECK(to_status_code(std::make_error_code(std::errc::operation_not_permitted)) == fx_permission_denied);
	CHECK(to_status_code(std::make_error_code(std::errc::directory_not_empty)) == fx_failure);
}

TEST_CASE("sftp fs backend file io", "[unit][sftp]") {
	backend_fixture fx;

	SECTION("write, read back, eof") {
		auto h = fx.open_for("/f.txt", fxf_write|fxf_creat);
		fx.backend.on_write_file(2, h, 0, fx.to_data("hello sftp"));
		CHECK(fx.iface.last == "ok");
		fx.backend.on_close_file(3, h);
		CHECK(fx.iface.last == "ok");

		h = fx.open_for("/f.txt", fxf_read);
		fx.backend.on_read_file(4, h, 0, 1024);
		CHECK(fx.iface.last == "data");
		CHECK(to_string_view(fx.iface.data) == "hello sftp");

		// read at the end gives eof
		fx.backend.on_read_file(5, h, 10, 1024);
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_eof);

		// partial read from offset
		fx.backend.on_read_file(6, h, 6, 4);
		CHECK(fx.iface.last == "data");
		CHECK(to_string_view(fx.iface.data) == "sftp");
		fx.backend.on_close_file(7, h);
	}
	SECTION("write at offset") {
		auto h = fx.open_for("/f.txt", fxf_write|fxf_read|fxf_creat);
		fx.backend.on_write_file(2, h, 0, fx.to_data("0123456789"));
		fx.backend.on_write_file(3, h, 3, fx.to_data("XYZ"));
		CHECK(fx.iface.last == "ok");
		fx.backend.on_read_file(4, h, 0, 100);
		CHECK(to_string_view(fx.iface.data) == "012XYZ6789");
	}
	SECTION("append mode ignores the position") {
		fx.make_file("f.txt", "base");
		auto h = fx.open_for("/f.txt", fxf_write|fxf_append);
		fx.backend.on_write_file(2, h, 0, fx.to_data("-tail"));
		CHECK(fx.iface.last == "ok");
		fx.backend.on_close_file(3, h);
		std::ifstream f(fx.dir.path / "f.txt", std::ios::binary);
		std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		CHECK(content == "base-tail");
	}
	SECTION("truncate on open") {
		fx.make_file("f.txt", "long old content");
		auto h = fx.open_for("/f.txt", fxf_write|fxf_creat|fxf_trunc);
		fx.backend.on_close_file(2, h);
		CHECK(fs::file_size(fx.dir.path / "f.txt") == 0);
	}
	SECTION("exclusive create fails on existing file") {
		fx.make_file("f.txt");
		fx.backend.on_open_file(1, "/f.txt", open_mode(fxf_write|fxf_creat|fxf_excl), {});
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_failure);
	}
	SECTION("open nonexistent without create fails") {
		fx.backend.on_open_file(1, "/nope.txt", open_mode(fxf_read), {});
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_no_such_file);
	}
#ifndef _WIN32
	SECTION("create with permissions") {
		file_attributes attrs;
		attrs.permissions = 0600;
		fx.backend.on_open_file(1, "/f.txt", open_mode(fxf_write|fxf_creat), attrs);
		REQUIRE(fx.iface.last == "open_file");
		auto st = fs::status(fx.dir.path / "f.txt");
		CHECK((std::uint32_t(st.permissions()) & 0777) == 0600);
	}
#endif
	SECTION("invalid handle") {
		fx.backend.on_read_file(1, "bogus", 0, 10);
		CHECK(fx.iface.last == "error");
		fx.backend.on_write_file(2, "bogus", 0, fx.to_data("x"));
		CHECK(fx.iface.last == "error");
		fx.backend.on_close_file(3, "bogus");
		CHECK(fx.iface.last == "error");
	}
}

TEST_CASE("sftp fs backend stat and setstat", "[unit][sftp]") {
	backend_fixture fx;

	SECTION("stat file") {
		fx.make_file("f.txt", "0123456789");
		fx.backend.on_stat(1, "/f.txt", true);
		REQUIRE(fx.iface.last == "stat");
		CHECK(fx.iface.attrs.size == 10);
		REQUIRE(fx.iface.attrs.permissions);
		CHECK((*fx.iface.attrs.permissions & 0170000) == 0100000); // regular file bits
#ifndef _WIN32
		CHECK(fx.iface.attrs.uid);
#endif
		CHECK(fx.iface.attrs.mtime);
	}
	SECTION("stat missing file") {
		fx.backend.on_stat(1, "/nope", true);
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_no_such_file);
	}
	SECTION("fstat via handle") {
		fx.make_file("f.txt", "12345");
		auto h = fx.open_for("/f.txt", fxf_read);
		fx.backend.on_stat_file(2, h);
		REQUIRE(fx.iface.last == "stat");
		CHECK(fx.iface.attrs.size == 5);
	}
	SECTION("setstat size and permissions") {
		fx.make_file("f.txt", "0123456789");
		file_attributes attrs;
		attrs.size = 4;
		attrs.permissions = 0640;
		fx.backend.on_setstat(1, "/f.txt", attrs);
		CHECK(fx.iface.last == "ok");
		CHECK(fs::file_size(fx.dir.path / "f.txt") == 4);
#ifndef _WIN32
		auto st = fs::status(fx.dir.path / "f.txt");
		CHECK((std::uint32_t(st.permissions()) & 0777) == 0640);
#endif
	}
	SECTION("fsetstat via handle") {
		fx.make_file("f.txt", "0123456789");
		auto h = fx.open_for("/f.txt", fxf_write);
		file_attributes attrs;
		attrs.size = 2;
		fx.backend.on_setstat_file(2, h, attrs);
		CHECK(fx.iface.last == "ok");
		CHECK(fs::file_size(fx.dir.path / "f.txt") == 2);
	}
	SECTION("setstat times") {
		fx.make_file("f.txt");
		file_attributes attrs;
		attrs.atime = 1000000;
		attrs.mtime = 2000000;
		fx.backend.on_setstat(1, "/f.txt", attrs);
		CHECK(fx.iface.last == "ok");
		fx.backend.on_stat(2, "/f.txt", true);
		REQUIRE(fx.iface.last == "stat");
		CHECK(fx.iface.attrs.mtime == 2000000);
#ifndef _WIN32
		CHECK(fx.iface.attrs.atime == 1000000);
#endif
	}
}

TEST_CASE("sftp fs backend directories", "[unit][sftp]") {
	backend_fixture fx;

	SECTION("mkdir, list, rmdir") {
		fx.backend.on_mkdir(1, "/d", {});
		CHECK(fx.iface.last == "ok");
		CHECK(fs::is_directory(fx.dir.path / "d"));

		fx.make_file("a.txt", "aaa");
		fx.backend.on_open_dir(2, "/");
		REQUIRE(fx.iface.last == "open_dir");
		auto h = fx.iface.handle;
		fx.backend.on_read_dir(3, h);
		REQUIRE(fx.iface.last == "read_dir");
		REQUIRE(fx.iface.files.size() == 2);
		bool found_dir = false, found_file = false;
		for(auto&& fi : fx.iface.files) {
			if(fi.filename == "d") {
				found_dir = true;
				CHECK(fi.longname.substr(0, 1) == "d");
			}
			if(fi.filename == "a.txt") {
				found_file = true;
				CHECK(fi.attrs.size == 3);
				CHECK(!fi.longname.empty());
			}
		}
		CHECK(found_dir);
		CHECK(found_file);

		fx.backend.on_read_dir(4, h);
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_eof);
		fx.backend.on_close_dir(5, h);
		CHECK(fx.iface.last == "ok");

		fx.backend.on_remove_dir(6, "/d");
		CHECK(fx.iface.last == "ok");
		CHECK(!fs::exists(fx.dir.path / "d"));
	}
	SECTION("read_dir batching") {
		for(int i = 0; i != 100; ++i) {
			fx.make_file("file_" + std::to_string(i));
		}
		fx.backend.on_open_dir(1, "/");
		auto h = fx.iface.handle;
		fx.backend.on_read_dir(2, h);
		REQUIRE(fx.iface.last == "read_dir");
		std::size_t total = fx.iface.files.size();
		CHECK(total == max_read_dir_count);
		fx.backend.on_read_dir(3, h);
		REQUIRE(fx.iface.last == "read_dir");
		total += fx.iface.files.size();
		CHECK(total == 100);
		fx.backend.on_read_dir(4, h);
		CHECK(fx.iface.code == fx_eof);
	}
	SECTION("mkdir on existing fails") {
		fx.backend.on_mkdir(1, "/d", {});
		fx.backend.on_mkdir(2, "/d", {});
		CHECK(fx.iface.last == "error");
	}
	SECTION("rmdir of non-empty dir fails") {
		fx.backend.on_mkdir(1, "/d", {});
		fx.make_file("d/inner.txt");
		fx.backend.on_remove_dir(2, "/d");
		CHECK(fx.iface.last == "error");
		CHECK(fs::exists(fx.dir.path / "d"));
	}
	SECTION("rmdir of file fails") {
		fx.make_file("f.txt");
		fx.backend.on_remove_dir(1, "/f.txt");
		CHECK(fx.iface.last == "error");
		CHECK(fs::exists(fx.dir.path / "f.txt"));
	}
	SECTION("open_dir on file fails") {
		fx.make_file("f.txt");
		fx.backend.on_open_dir(1, "/f.txt");
		CHECK(fx.iface.last == "error");
	}
}

TEST_CASE("sftp fs backend remove and rename", "[unit][sftp]") {
	backend_fixture fx;

	SECTION("remove file") {
		fx.make_file("f.txt");
		fx.backend.on_remove_file(1, "/f.txt");
		CHECK(fx.iface.last == "ok");
		CHECK(!fs::exists(fx.dir.path / "f.txt"));

		fx.backend.on_remove_file(2, "/f.txt");
		CHECK(fx.iface.last == "error");
	}
	SECTION("remove refuses directory") {
		fx.backend.on_mkdir(1, "/d", {});
		fx.backend.on_remove_file(2, "/d");
		CHECK(fx.iface.last == "error");
		CHECK(fs::exists(fx.dir.path / "d"));
	}
#ifndef _WIN32
	SECTION("remove symlink removes the link only") {
		fx.make_file("target.txt");
		fx.backend.on_symlink(1, "/link", "target.txt");
		CHECK(fx.iface.last == "ok");
		fx.backend.on_remove_file(2, "/link");
		CHECK(fx.iface.last == "ok");
		CHECK(!fs::exists(fx.dir.path / "link"));
		CHECK(fs::exists(fx.dir.path / "target.txt"));
	}
#endif
	SECTION("rename") {
		fx.make_file("a.txt", "data");
		fx.backend.on_rename(1, "/a.txt", "/b.txt");
		CHECK(fx.iface.last == "ok");
		CHECK(!fs::exists(fx.dir.path / "a.txt"));
		CHECK(fs::exists(fx.dir.path / "b.txt"));
	}
	SECTION("rename fails if target exists") {
		fx.make_file("a.txt", "aaa");
		fx.make_file("b.txt", "bbb");
		fx.backend.on_rename(1, "/a.txt", "/b.txt");
		CHECK(fx.iface.last == "error");
		std::ifstream f(fx.dir.path / "b.txt");
		std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		CHECK(content == "bbb");
	}
}

TEST_CASE("sftp fs backend links and paths", "[unit][sftp]") {
	backend_fixture fx;

#ifndef _WIN32
	SECTION("symlink and readlink") {
		fx.make_file("target.txt");
		fx.backend.on_symlink(1, "/link", "target.txt");
		CHECK(fx.iface.last == "ok");
		fx.backend.on_readlink(2, "/link");
		REQUIRE(fx.iface.last == "path");
		CHECK(fx.iface.path == "target.txt");
	}
	SECTION("lstat vs stat on symlink") {
		fx.make_file("target.txt", "12345");
		fx.backend.on_symlink(1, "/link", "target.txt");
		fx.backend.on_stat(2, "/link", true);
		REQUIRE(fx.iface.last == "stat");
		CHECK((*fx.iface.attrs.permissions & 0170000) == 0100000); // followed to the file
		fx.backend.on_stat(3, "/link", false);
		REQUIRE(fx.iface.last == "stat");
		CHECK((*fx.iface.attrs.permissions & 0170000) == 0120000); // the link itself
	}
#endif
	SECTION("realpath") {
		fx.backend.on_realpath(1, ".");
		REQUIRE(fx.iface.last == "path");
		CHECK(fx.iface.path == "/");
		fx.backend.on_mkdir(2, "/d", {});
		fx.backend.on_realpath(3, "/d/../d/.");
		REQUIRE(fx.iface.last == "path");
		CHECK(fx.iface.path == "/d");
	}
	SECTION("extended request is unsupported") {
		fx.backend.on_extended(1, "test@ext", {});
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_op_unsupported);
	}
}

TEST_CASE("sftp fs backend path confinement", "[unit][sftp]") {
	backend_fixture fx;
	fx.make_file("secret.txt");

	SECTION("dot dot escapes are refused") {
		fx.backend.on_remove_file(1, "/../../etc/passwd");
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_permission_denied);
		fx.backend.on_open_file(2, "../secret.txt", open_mode(fxf_read), {});
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_permission_denied);
	}
#ifndef _WIN32
	SECTION("access through escaping symlink is refused") {
		fs::create_symlink("/etc", fx.dir.path / "escape");
		fx.backend.on_open_file(1, "/escape/passwd", open_mode(fxf_read), {});
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_permission_denied);
		fx.backend.on_open_dir(2, "/escape");
		CHECK(fx.iface.last == "error");
		CHECK(fx.iface.code == fx_permission_denied);
	}
#endif
	SECTION("operations inside the root still work") {
		fx.backend.on_open_file(1, "/secret.txt", open_mode(fxf_read), {});
		CHECK(fx.iface.last == "open_file");
	}
}

}
