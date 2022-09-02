
#include "log.hpp"

#define CATCH_CONFIG_RUNNER
#include <external/catch/catch.hpp>

using namespace securepath;

stdout_logger& securepath::ssh::test::test_log() {
    static stdout_logger log(stdout_logger::log_none);
    return log;
}

int main(int argc, char* argv[]) {
	using namespace Catch::clara;

    Catch::Session session;
    bool show_logging = false;

    auto cli = session.cli()
        | Opt(show_logging)
             ["--show-ssh-log"]
             ("Show ssh log");

    session.cli(cli);

    auto ret = session.applyCommandLine( argc, argv );
    if (ret) {
        return ret;
    }
    if(show_logging) {
    	ssh::test::test_log().set_level(stdout_logger::log_all);
    }

    return session.run();
}