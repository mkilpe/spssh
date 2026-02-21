# spssh

SSH Version 2 client/server library for building SSH-based protocols with modern C++20.

## Features

- Full SSH transport layer (RFC 4253) with re-keying support
- SSH client and server implementations
- SFTP client and server (RFC 4254 / draft-ietf-secsh-filexfer) (still missing some bits)
- Pluggable authentication: password, public key, host-based, keyboard-interactive
- Configurable algorithm suites

**Key exchange:** X25519, DH Group14, DH Group16

**Ciphers:** AES-256-GCM (including OpenSSH variant), AES-256-CTR

**MACs:** AES-256-GCM (AEAD/implicit), HMAC-SHA2-256

**Host key types:** RSA, Ed25519, ECDSA P-256

**Crypto backends:** Nettle or Crypto++

## Requirements

- C++20 compiler
- CMake 3.12+
- Nettle **or** Crypto++ (crypto backend)
- Asio (optional, required for the test client/server tools)
- Catch2 (optional, required for tests; place under `external/`)

## Building

Copy and edit the config file:

```sh
cp cmake.config.example cmake.config
# edit cmake.config to select your crypto backend and set include paths
```

Then build:

```sh
cmake -B build
cmake --build build
```

Or using the generated Makefile directly after a prior cmake run:

```sh
make
```

### cmake.config options

| Option | Description |
|---|---|
| `USE_NETTLE` | Enable Nettle crypto backend |
| `USE_CRYPTOPP` | Enable Crypto++ crypto backend |
| `Asio_INCLUDE_DIR` | Path to standalone Asio include directory |
| `CMAKE_BUILD_TYPE` | `Debug` (default) or `Release` |

## Project layout

```
ssh/
  core/       – SSH transport, key exchange, packet layer, channel handling
  crypto/     – Crypto abstraction (cipher, MAC, KEX, keys, random)
  client/     – SSH client (ssh_client, client_config, auth)
  server/     – SSH server (ssh_server, server_config, auth)
  services/
    sftp/     – SFTP client and server
tools/
  test_client/ – Example SSH client using Asio
  test_server/ – Example SSH server using Asio
test/          – Unit tests (Catch2)
```

## Usage overview

### Server

Subclass `server_auth_service` and implement the authentication callbacks, then create an `ssh_server` with a `server_config`:

```cpp
#include "ssh/server/ssh_server.hpp"

securepath::ssh::server_config cfg;
cfg.set_host_keys_for_server({my_private_key});
cfg.algorithms = /* your supported_algorithms */;

// ssh_server takes an out_buffer and logger; drive it by feeding
// received network data via handle_input() and draining the output buffer.
securepath::ssh::ssh_server server(cfg, log, out_buf);
```

### Client

```cpp
#include "ssh/client/ssh_client.hpp"

securepath::ssh::client_config cfg;
cfg.username = "user";
cfg.password = "secret";   // or set a private key for pubkey auth
cfg.algorithms = /* your supported_algorithms */;

securepath::ssh::ssh_client client(cfg, log, out_buf);
client.start_auth("ssh-connection");
```

### SFTP client

Obtain a channel from a connected `ssh_client` and create an `sftp_client` on top of it:

```cpp
#include "ssh/services/sftp/sftp_client.hpp"

auto sftp = std::make_unique<securepath::ssh::sftp::sftp_client>(callback, transport, local_info);
auto handle = sftp->open_file("/remote/path", sftp::open_mode::read);
```

### Authentication configuration (server)

```cpp
securepath::ssh::auth_config auth_cfg;
auth_cfg.service_auth["ssh-connection"] = {
    .required = {},                                        // no mandatory methods
    .allowed  = auth_type::public_key | auth_type::password,
    .num_req  = 1                                          // any one method suffices
};
auth_cfg.num_of_tries = 5;
```

## License

See [LICENSE](LICENSE).
