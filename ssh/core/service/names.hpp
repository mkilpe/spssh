#ifndef SPSSH_CORE_SERVICE_NAMES_HEADER
#define SPSSH_CORE_SERVICE_NAMES_HEADER

#include <string_view>

namespace securepath::ssh {

inline std::string_view user_auth_service_name{"ssh-userauth"};
inline std::string_view connection_service_name{"ssh-connection"};

}

#endif