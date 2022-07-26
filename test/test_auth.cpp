
#include "configs.hpp"
#include "random.hpp"
#include "util.hpp"
#include "test_buffers.hpp"

#include "ssh/client/auth_service.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/server/ssh_server.hpp"
#include "test/util/server_auth_service.hpp"

/* Tested:
	+ no auth call to get methods
 	+ basic use of password
 	+ basic use of key (check and auth)
 	+ basic use of host-based
 	+ basic use of interactive
 	+ wrong password
 	+ wrong key
 	+ bad domain/user with host-based
 	+ bad data with interactive
 	+ no matching methods
 	+ multiple methods required
 	+ multi-step interactive
 	+ async/pending auth
 	+ no auth required
 	+ num of tries
 	+ service changes / user changes
*/


namespace securepath::ssh::test {
namespace {

struct client_auth_data {
	std::string banner;
	auth_try last_try;
	auth_info success;
	std::vector<std::string> last_methods;

	int fails{};
	int succeeds{};

	std::string interactive_name;
	std::string interactive_instruction;
	std::vector<std::vector<std::string>> interactive_respond;
	std::size_t interactive_state{};
};

class client_test_auth_service : public client_auth_service {
public:
	client_test_auth_service(ssh_transport& transport, client_auth_data& d)
	: client_auth_service(transport)
	, data(d)
	{}

	void on_banner(std::string_view b) override {
		data.banner = b;
	}

	void on_auth_fail(auth_try t, std::vector<std::string_view> const& methods) override {
		log_.log(logger::error, "test: auth fail [{}]", to_string(t.type));
		data.last_try = t;
		data.last_methods.clear();
		for(auto v : methods) {
			data.last_methods.push_back(std::string(v));
		}
		++data.fails;
	}

	void on_auth_success(auth_try t, std::vector<std::string_view> const& methods) override {
		log_.log(logger::error, "test: auth success [{}]", to_string(t.type));
		data.last_try = t;
		data.last_methods.clear();
		for(auto v : methods) {
			data.last_methods.push_back(std::string(v));
		}
		++data.succeeds;
	}

	void on_success(std::string_view username, std::string_view service) override {
		data.success.user = username;
		data.success.service = service;
	}

	interactive_result on_interactive(interactive_request const& req, std::vector<std::string>& results) override {
		data.interactive_name = req.name;
		data.interactive_instruction = req.instruction;
		if(data.interactive_respond.size() > data.interactive_state) {
			results = data.interactive_respond[data.interactive_state++];
			return interactive_result::data;
		}
		return interactive_result::cancelled;
	}

	client_auth_data& data;
};

struct test_client : test_context, client_config, ssh_client {
	test_client(logger& l = test_log())
	: test_context(l, "[client] ")
	, client_config(test_client_config())
	, ssh_client(*this, slog, out_buf)
	{
		// always try to use dummy-service
		service = "dummy-service";
	}

	std::unique_ptr<auth_service> construct_auth() override {
		return std::make_unique<client_test_auth_service>(*this, data);
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			return std::make_unique<dummy_service>();
		}
		return nullptr;
	}

	void set_password(std::string user, std::string pass) {
		username = user;
		password = pass;
	}

	void send_no_auth() {
		static_cast<client_auth_service&>(*service_).no_authentication(username, service);
	}

	void send_password() {
		static_cast<client_auth_service&>(*service_).authenticate(username, service, password);
	}

	void send_public_key(std::string user, ssh_private_key key) {
		static_cast<client_auth_service&>(*service_).authenticate(user, service, key);
	}

	void send_public_key_with_check(std::string user, ssh_private_key key) {
		static_cast<client_auth_service&>(*service_).authenticate_with_key_check(user, service, key);
	}

	void send_host(std::string user, ssh_private_key key, std::string_view domain, std::string_view host_user) {
		static_cast<client_auth_service&>(*service_).authenticate_host(user, service, key, domain, host_user);
	}

	void send_interactive(std::string user) {
		data.interactive_state = 0;
		static_cast<client_auth_service&>(*service_).authenticate_interactive(user, service, {});
	}

	client_auth_data data;
};

struct test_server : test_context, server_config, ssh_server {
	test_server(logger& l = test_log())
	: test_context(l, "[server] ")
	, server_config(test_server_config())
	, ssh_server(*this, slog, out_buf)
	{
		auth.banner = "test-banner";
	}

	std::unique_ptr<auth_service> construct_auth() override {
		return std::make_unique<server_test_auth_service>(*this, auth, std::move(auth_data));
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			return std::make_unique<dummy_service>();
		}
		return nullptr;
	}

	bool check_service() const {
		return service_ && service_->name() == "dummy-service";
	}

	test_auth_data auth_data;
};

template<typename Cont, typename Value>
bool has_value(Cont const& c, Value const& v) {
	return std::find(c.begin(), c.end(), v) != c.end();
}

}

TEST_CASE("no auth for methods", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	client.set_password("test-user", "hophiphap");
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_type::password|auth_type::hostbased, 1};

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	client.send_no_auth();

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	CHECK(client.data.last_try.type == auth_type::none);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.size() == 2);
	CHECK(has_value(client.data.last_methods, to_string(auth_type::password)));
	CHECK(has_value(client.data.last_methods, to_string(auth_type::hostbased)));
}

void success_check(test_client& client, test_server& server) {
	REQUIRE(client.state() == ssh_state::transport);
	REQUIRE(server.state() == ssh_state::transport);
	REQUIRE(client.user_authenticated());
	REQUIRE(server.user_authenticated());

	REQUIRE(client.data.banner == "test-banner");
	REQUIRE(client.data.success.user == "test-user");
	REQUIRE(client.data.success.service == "dummy-service");

	REQUIRE(client.data.fails == 0);
	REQUIRE(server.check_service());
}

TEST_CASE("password auth test", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	client.set_password("test-user", "hophiphap");
	server.auth_data.add_password("test-user", "hophiphap");
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::password), 1};

	CHECK(run(client, server));

	client.send_password();

	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("public key auth test", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	ssh_private_key key = cctx.test_ed25519_private_key();

	server.auth_data.add_pk("test-user", key.public_key().fingerprint(client.crypto(), client.call_context()));
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::public_key), 1};

	CHECK(run(client, server));

	client.send_public_key("test-user", key);

	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("public key auth test with check", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	ssh_private_key key = cctx.test_ed25519_private_key();

	server.auth_data.add_pk("test-user", key.public_key().fingerprint(client.crypto(), client.call_context()));
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::public_key), 1};

	CHECK(run(client, server));

	client.send_public_key_with_check("test-user", key);

	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("hostbased auth test", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	ssh_private_key key = cctx.test_ed25519_private_key();

	server.auth_data.add_host(
		"test-user",
		key.public_key().fingerprint(client.crypto(), client.call_context()),
		"mydomain.net",
		"testuser");

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::hostbased), 1};

	CHECK(run(client, server));

	client.send_host("test-user", key, "mydomain.net", "testuser");

	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("interactive auth test 1", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	client.data.interactive_respond = {{"some", "other"}};

	server.auth_data.add_interactive("test-user"
		, {interactive_request{"test", "string",
			{interactive_prompt{true, "name"}
			,interactive_prompt{false, "pass"}}}}
		, client.data.interactive_respond);

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::interactive), 1};

	CHECK(run(client, server));

	client.send_interactive("test-user");

	CHECK(run(client, server));

	success_check(client, server);

	CHECK(client.data.interactive_name == "test");
	CHECK(client.data.interactive_instruction == "string");
}


TEST_CASE("interactive auth test 2", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	//this one has multiple requests
	client.data.interactive_respond = {{"some", "other"}, {"xxx"}, {"some", "other", "iii", "aaaaaa"}};

	server.auth_data.add_interactive("test-user"
		, {interactive_request{"test", "string",
			{interactive_prompt{true, "name"}
			,interactive_prompt{false, "pass"}}}
		  ,interactive_request{"aaa", "bbb",
			{interactive_prompt{false, "data"}}}
		  ,interactive_request{"zzz", "xxx",
			{interactive_prompt{true, "info1"}
			,interactive_prompt{false, "info2"}
			,interactive_prompt{false, "info3"}}}}
		, client.data.interactive_respond);

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::interactive), 1};

	CHECK(run(client, server));

	client.send_interactive("test-user");

	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("interactive auth test 3", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	client.data.interactive_respond = {{}};

	server.auth_data.add_interactive("test-user"
		, {interactive_request{"test", "string", {}}}
		, client.data.interactive_respond);

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::interactive), 1};

	CHECK(run(client, server));

	client.send_interactive("test-user");

	CHECK(run(client, server));

	success_check(client, server);

	CHECK(client.data.interactive_name == "test");
	CHECK(client.data.interactive_instruction == "string");
}

TEST_CASE("bad password auth test", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	client.set_password("test-user", "hophiphap");
	server.auth_data.add_password("test-user", "hophiphap11");
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::password), 1};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));

	client.send_password();

	// goes into error state
	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.error() == ssh_error_code::ssh_no_more_auth_methods_available);
	CHECK(server.error() == ssh_error_code::ssh_no_more_auth_methods_available);

	CHECK(client.data.last_try.type == auth_type::password);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.size() == 1);
	CHECK(has_value(client.data.last_methods, to_string(auth_type::password)));
}


TEST_CASE("bad public key auth test", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	ssh_private_key key = cctx.test_ed25519_private_key();

	server.auth_data.add_pk("test-user", "somesome");
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::public_key), 1};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));

	client.send_public_key("test-user", key);

	// goes into error state
	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.error() == ssh_error_code::ssh_no_more_auth_methods_available);
	CHECK(server.error() == ssh_error_code::ssh_no_more_auth_methods_available);

	CHECK(client.data.last_try.type == auth_type::public_key);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.size() == 1);
	CHECK(has_value(client.data.last_methods, to_string(auth_type::public_key)));
}


TEST_CASE("bad hostbased auth test", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	ssh_private_key key = cctx.test_ed25519_private_key();

	server.auth_data.add_host(
		"test-user",
		key.public_key().fingerprint(client.crypto(), client.call_context()),
		"otherdomain.net",
		"testuser");

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::hostbased), 1};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));

	client.send_host("test-user", key, "mydomain.net", "testuser");

	// goes into error state
	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.error() == ssh_error_code::ssh_no_more_auth_methods_available);
	CHECK(server.error() == ssh_error_code::ssh_no_more_auth_methods_available);

	CHECK(client.data.last_try.type == auth_type::hostbased);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.size() == 1);
	CHECK(has_value(client.data.last_methods, to_string(auth_type::hostbased)));
}


TEST_CASE("bad interactive auth test 1", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	client.data.interactive_respond = {{"some", "other"}};

	server.auth_data.add_interactive("test-user"
		, {interactive_request{"test", "string",
			{interactive_prompt{true, "name"}
			,interactive_prompt{false, "pass"}}}}
		, {{"some", "not that"}});

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::interactive), 1};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));

	client.send_interactive("test-user");

	// goes into error state
	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.error() == ssh_error_code::ssh_no_more_auth_methods_available);
	CHECK(server.error() == ssh_error_code::ssh_no_more_auth_methods_available);

	CHECK(client.data.last_try.type == auth_type::interactive);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.size() == 1);
	CHECK(has_value(client.data.last_methods, to_string(auth_type::interactive)));
}

TEST_CASE("bad interactive auth test 2", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	//this one has multiple requests
	client.data.interactive_respond = {{"some", "other"}, {"xxx"}, {"some", "other", "iii", "aaaaaa"}};

	server.auth_data.add_interactive("test-user"
		, {interactive_request{"test", "string",
			{interactive_prompt{true, "name"}
			,interactive_prompt{false, "pass"}}}
		  ,interactive_request{"aaa", "bbb",
			{interactive_prompt{false, "data"}}}
		  ,interactive_request{"zzz", "xxx",
			{interactive_prompt{true, "info1"}
			,interactive_prompt{false, "info2"}
			,interactive_prompt{false, "info3"}}}}
		, {{"some", "other"}, {"xxx"}, {"some", "other", "iii", "aaaxxxaaa"}});


	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::interactive), 1};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));

	client.send_interactive("test-user");

	// goes into error state
	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.error() == ssh_error_code::ssh_no_more_auth_methods_available);
	CHECK(server.error() == ssh_error_code::ssh_no_more_auth_methods_available);

	CHECK(client.data.last_try.type == auth_type::interactive);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.size() == 1);
	CHECK(has_value(client.data.last_methods, to_string(auth_type::interactive)));
}


TEST_CASE("bad interactive auth test 3", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	// wrong amount of response
	client.data.interactive_respond = {{"other"}};

	server.auth_data.add_interactive("test-user"
		, {interactive_request{"test", "string",
			{interactive_prompt{true, "name"}
			,interactive_prompt{false, "pass"}}}}
		, {{"other", "some"}});

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::interactive), 1};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));

	client.send_interactive("test-user");

	// goes into error state
	CHECK(!run(client, server));

	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.error() == ssh_error_code::ssh_no_more_auth_methods_available);
	CHECK(server.error() == ssh_error_code::ssh_no_more_auth_methods_available);

	CHECK(client.data.last_try.type == auth_type::interactive);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.size() == 1);
	CHECK(has_value(client.data.last_methods, to_string(auth_type::interactive)));
}

TEST_CASE("no matching methods auth test", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	client.set_password("test-user", "hophiphap");

	// don't allow any authentication methods
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(), 1};
	server.auth.num_of_tries = 3;

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	// try with password
	client.send_password();

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::password);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.empty());

	// try with public key
	client.send_public_key("test-user", key);

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::public_key);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.empty());

	//try with host-based
	client.send_host("test-user", key, "mydomain.net", "testuser");

	// we allow 3 tries, so this should error
	CHECK(!run(client, server));
	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(client.data.last_try.type == auth_type::hostbased);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_methods.empty());
}


TEST_CASE("no auth required", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	//set the username
	client.set_password("test-user", "hophiphap");
	server.auth.service_auth["dummy-service"] = req_auth{{}, {}, 0};

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_no_auth();

	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("multi methods required 1", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	client.set_password("test-user", "hophiphap");

	server.auth_data.add_password("test-user", "hophiphap");
	server.auth_data.add_pk("test-user", key.public_key().fingerprint(client.crypto(), client.call_context()));
	server.auth_data.add_host(
		"test-user",
		key.public_key().fingerprint(client.crypto(), client.call_context()),
		"otherdomain.net",
		"testuser");
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_type::public_key|auth_type::password|auth_type::hostbased, 2};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_password();

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::password);
	CHECK(client.data.last_try.username == "test-user");

	client.send_public_key("test-user", key);
	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("multi methods required 2", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	client.set_password("test-user", "hophiphap");

	server.auth_data.add_password("test-user", "hophiphap");
	server.auth_data.add_pk("test-user", key.public_key().fingerprint(client.crypto(), client.call_context()));
	server.auth_data.add_host(
		"test-user",
		key.public_key().fingerprint(client.crypto(), client.call_context()),
		"mydomain.net",
		"testuser");
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_type::public_key|auth_type::password|auth_type::hostbased, 2};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_host("test-user", key, "mydomain.net", "testuser");

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::hostbased);
	CHECK(client.data.last_try.username == "test-user");

	client.send_password();
	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("multi methods required 3", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	client.set_password("test-user", "hophiphap");

	server.auth_data.add_password("test-user", "hophiphap");
	server.auth_data.add_pk("test-user", key.public_key().fingerprint(client.crypto(), client.call_context()));
	server.auth_data.add_host(
		"test-user",
		key.public_key().fingerprint(client.crypto(), client.call_context()),
		"mydomain.net",
		"testuser");
	server.auth.service_auth["dummy-service"] = req_auth{auth_bits(auth_type::public_key), auth_type::public_key|auth_type::password|auth_type::hostbased, 2};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_host("test-user", key, "mydomain.net", "testuser");

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::hostbased);
	CHECK(client.data.last_try.username == "test-user");

	client.send_password();
	CHECK(run(client, server));

	// both of the authentications succeed but the user is not authenticated because public_key auth is required
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());
}


TEST_CASE("multi methods required 4", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	client.set_password("test-user", "hophiphap");

	server.auth_data.add_password("test-user", "hophiphap");
	server.auth_data.add_pk("test-user", key.public_key().fingerprint(client.crypto(), client.call_context()));
	server.auth_data.add_host(
		"test-user",
		key.public_key().fingerprint(client.crypto(), client.call_context()),
		"mydomain.net",
		"testuser");
	server.auth.service_auth["dummy-service"] = req_auth{auth_bits(auth_type::public_key), auth_type::public_key|auth_type::password|auth_type::hostbased, 2};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_host("test-user", key, "mydomain.net", "testuser");

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::hostbased);
	CHECK(client.data.last_try.username == "test-user");

	client.send_public_key("test-user", key);
	CHECK(run(client, server));

	success_check(client, server);
}


TEST_CASE("interrupted interactive auth test", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;

	client.set_password("test-user", "hophiphap");
	client.data.interactive_respond = {{"some", "other"}};

	server.auth_data.add_interactive("test-user"
		, {interactive_request{"test", "string",
			{interactive_prompt{true, "name"}
			,interactive_prompt{false, "pass"}}}}
		, client.data.interactive_respond);

	server.auth_data.add_password("test-user", "ssss");

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_type::interactive|auth_type::password, 1};
	server.auth.num_of_tries = 2;

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_interactive("test-user");

	// send also password auth request which should cancel the first one
	client.send_password();

	// the client still answers to the interactive request but since the server already cancelled it, the server goes to error state
	CHECK(!run(client, server));
	CHECK(client.state() == ssh_state::disconnected);
	CHECK(server.state() == ssh_state::disconnected);

	CHECK(client.error() == ssh_protocol_error);
	CHECK(server.error() == ssh_protocol_error);
}

TEST_CASE("change of user", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	client.set_password("other-user", "hophiphap");

	server.auth_data.add_password("other-user", "hophiphap");
	server.auth_data.add_pk("test-user", key.public_key().fingerprint(client.crypto(), client.call_context()));

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_type::public_key|auth_type::password, 2};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_public_key("test-user", key);

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::public_key);
	CHECK(client.data.last_try.username == "test-user");

	// this uses different user, and so it succeeds but the state on server has been reset, the user is not yet authenticated
	client.send_password();
	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::password);
	CHECK(client.data.last_try.username == "other-user");
}


TEST_CASE("change of service", "[unit][crypto][auth]") {
	test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	client.set_password("test-user", "hophiphap");

	server.auth_data.add_password("test-user", "hophiphap");
	server.auth_data.add_pk("test-user", key.public_key().fingerprint(client.crypto(), client.call_context()));

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_type::public_key|auth_type::password, 2};
	server.auth.service_auth["other-service"] = req_auth{{}, auth_type::public_key|auth_type::password, 2};
	server.auth.num_of_tries = 1;

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_public_key("test-user", key);

	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::public_key);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_try.service == "dummy-service");

	// this uses different service, and so it succeeds but the state on server has been reset, the user is not yet authenticated
	client.service = "other-service";
	client.send_password();
	CHECK(run(client, server));
	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.last_try.type == auth_type::password);
	CHECK(client.data.last_try.username == "test-user");
	CHECK(client.data.last_try.service == "other-service");
}

// async/pending client test
namespace {

struct client_pending_auth_data {
	std::string name;
	std::string instruction;
	std::vector<std::string> req;
	std::vector<std::string> res;
};

class client_pending_test_auth_service : public client_auth_service {
public:
	client_pending_test_auth_service(ssh_transport& transport, client_pending_auth_data& d)
	: client_auth_service(transport)
	, data(d)
	{}

	void on_banner(std::string_view b) override {
	}

	void on_auth_fail(auth_try t, std::vector<std::string_view> const& methods) override {
	}

	void on_auth_success(auth_try t, std::vector<std::string_view> const& methods) override {
	}

	void on_success(std::string_view username, std::string_view service) override {
	}

	interactive_result on_interactive(interactive_request const& req, std::vector<std::string>& results) override {
		if(data.res.empty()) {
			data.name = req.name;
			data.instruction = req.instruction;
			data.req.clear();
			for(auto v : req.prompts) {
				data.req.push_back(std::string(v.text));
			}
			log_.log(logger::debug, "pending");
			return interactive_result::pending;
		}

		results = data.res;
		return interactive_result::data;
	}

	client_pending_auth_data& data;
};

struct pending_test_client : test_context, client_config, ssh_client {
	pending_test_client(logger& l = test_log())
	: test_context(l, "[client] ")
	, client_config(test_client_config())
	, ssh_client(*this, slog, out_buf)
	{
		// always try to use dummy-service
		service = "dummy-service";
	}

	std::unique_ptr<auth_service> construct_auth() override {
		return std::make_unique<client_pending_test_auth_service>(*this, data);
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			return std::make_unique<dummy_service>();
		}
		return nullptr;
	}

	void send_interactive(std::string user) {
		static_cast<client_pending_test_auth_service&>(*service_).authenticate_interactive(user, service, {});
	}

	client_pending_auth_data data;
};

}


TEST_CASE("pending interactive auth test", "[unit][crypto][auth]") {
	test_server server;
	pending_test_client client;

	crypto_test_context cctx;

	server.auth_data.add_interactive("test-user"
		, {interactive_request{"test", "string",
			{interactive_prompt{true, "name"}
			,interactive_prompt{false, "pass"}}}}
		, {{"test", "some"}});

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::interactive), 1};

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_interactive("test-user");

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	CHECK(client.data.name == "test");
	CHECK(client.data.instruction == "string");
	REQUIRE(client.data.req.size() == 2);
	CHECK(client.data.req[0] == "name");
	CHECK(client.data.req[1] == "pass");

	client.data.res = {"test", "some"};

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	CHECK(server.check_service());
}

// async/pending server tests
namespace {

struct server_pending_auth_data {
	std::string password;
	std::string fingerprint;
	std::string host;
	std::vector<std::string> res;

	std::optional<interactive_request> req;
};

class server_pending_test_auth_service : public server_auth_service {
public:
	server_pending_test_auth_service(ssh_transport& transport, auth_config const& aconf, server_pending_auth_data& data)
	: server_auth_service(transport, aconf)
	, transport(transport)
	, data(data)
	{}

	auth_state verify_password(auth_context const&, std::string_view password) override {
		if(data.password.empty()) {
			return auth_state::pending;
		}
		return data.password == password ? auth_state::succeeded : auth_state::failed;
	}

	auth_state verify_public_key(auth_context const&, ssh_public_key const& key) override {
		if(data.fingerprint.empty()) {
			return auth_state::pending;
		}
		return key.fingerprint(transport.crypto(), transport.call_context()) == data.fingerprint
			? auth_state::succeeded : auth_state::failed;
	}

	auth_state verify_host(auth_context const&, ssh_public_key const&, std::string_view fqdn, std::string_view) override {
		if(data.host.empty()) {
			return auth_state::pending;
		}
		return data.host == fqdn ? auth_state::succeeded : auth_state::failed;
	}

	auth_state start_interactive(auth_context const&, std::vector<std::string_view> const& submethods, interactive_request& request) override {
		if(!data.req) {
			return auth_state::pending;
		}

		request = *data.req;
		return auth_state::succeeded;
	}

	auth_interactive_state verify_interactive(auth_context const&, std::vector<std::string_view> const& responses) override {
		if(data.res.empty()) {
			return auth_interactive_state::pending;
		}

		return std::equal(data.res.begin(), data.res.end(), responses.begin(), responses.end(),
			[](auto const& v1, auto const& v2) {
				return v1 == v2;
			})
			? auth_interactive_state::succeeded : auth_interactive_state::failed;
	}

	void auth_succeeded(auth_context const&) override {
	}

	ssh_transport& transport;
	server_pending_auth_data& data;
};

struct pending_test_server : test_context, server_config, ssh_server {
	pending_test_server(logger& l = test_log())
	: test_context(l, "[server] ")
	, server_config(test_server_config())
	, ssh_server(*this, slog, out_buf)
	{
		auth.banner = "test-banner";
	}

	std::unique_ptr<auth_service> construct_auth() override {
		return std::make_unique<server_pending_test_auth_service>(*this, auth, data);
	}

	std::unique_ptr<ssh_service> construct_service(auth_info const& info) override {
		if(info.service == "dummy-service") {
			return std::make_unique<dummy_service>();
		}
		return nullptr;
	}

	bool check_service() const {
		return service_ && service_->name() == "dummy-service";
	}

	server_pending_auth_data data;
};
}

TEST_CASE("pending server password auth test", "[unit][crypto][auth]") {
	pending_test_server server;
	test_client client;

	client.set_password("test-user", "hophiphap");
	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::password), 1};

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_password();

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	//set the data and try again
	server.data.password = "hophiphap";

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	CHECK(server.check_service());
}

TEST_CASE("pending server public key auth test", "[unit][crypto][auth]") {
	pending_test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::public_key), 1};

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_public_key("test-user", key);

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	//set the data and try again
	server.data.fingerprint = key.public_key().fingerprint(client.crypto(), client.call_context());

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	CHECK(server.check_service());
}

TEST_CASE("pending server hostbased auth test", "[unit][crypto][auth]") {
	pending_test_server server;
	test_client client;

	crypto_test_context cctx;
	ssh_private_key key = cctx.test_ed25519_private_key();

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::hostbased), 1};

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_host("test-user", key, "mydomain.net", "testuser");

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	//set the data and try again
	server.data.host = "mydomain.net";

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	CHECK(server.check_service());
}


TEST_CASE("pending server interactive auth test", "[unit][crypto][auth]") {
	pending_test_server server;
	test_client client;

	client.data.interactive_respond = {{"hipshops"}};

	server.auth.service_auth["dummy-service"] = req_auth{{}, auth_bits(auth_type::interactive), 1};

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	client.send_interactive("test-user");

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	//set the data and try again
	server.data.req = interactive_request{"test", "other", {interactive_prompt{false, "pass"}}};

	CHECK(run(client, server));

	CHECK(!client.user_authenticated());
	CHECK(!server.user_authenticated());

	server.data.res = {"hipshops"};

	CHECK(run(client, server));

	CHECK(client.state() == ssh_state::transport);
	CHECK(server.state() == ssh_state::transport);

	CHECK(server.check_service());
}

}