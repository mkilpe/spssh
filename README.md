# spssh

![ci](https://github.com/mkilpe/spssh/actions/workflows/ci.yml/badge.svg)

SSH Version 2 client/server library for building SSH-based protocols with modern C++20.

## Features

- Full SSH transport layer (RFC 4253) with re-keying support
- SSH client and server implementations
- SFTP version 3 client and server (draft-ietf-secsh-filexfer-02), interoperable with OpenSSH
- Local filesystem SFTP server backend with path confinement, or implement your own backend
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
  test_client/ – Example SSH client using Asio, with an interactive SFTP mode
  test_server/ – Example SSH server using Asio, serves a directory over SFTP
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

Implement `sftp::sftp_client_callback` to receive the results, then open a `"session"`
channel on a connected `ssh_connection` that constructs the `sftp_client` on top of it
(see `tools/test_client` for a complete example):

```cpp
#include "ssh/services/sftp/sftp_client.hpp"

// in namespace securepath::ssh
auto ch = connection.open_channel("session",
	[&](transport_base& t, channel_side_info info) {
		return std::make_unique<sftp::sftp_client>(callback, t, info);
	});

// after the callback receives on_version, the commands are available;
// each returns a call handle that identifies the matching result callback
auto handle = sftp_client->open_file("/remote/path", sftp::fxf_read);
```

### SFTP server

Register a `"session"` channel type that upgrades itself to an SFTP server when the
client requests the sftp subsystem. `local_fs_server_backend` serves a local directory
and refuses any path escaping it; implement `sftp::sftp_server_backend` for custom
storage (see `tools/test_server` for a complete example):

```cpp
#include "ssh/services/sftp/local_fs_backend.hpp"
#include "ssh/services/sftp/sftp_session_channel.hpp"

// in namespace securepath::ssh
connection.add_channel_type("session",
	[root](transport_base& t, channel_side_info info) {
		return std::make_unique<sftp::sftp_session_channel>(t, info,
			[&t, root]() {
				return std::make_shared<sftp::local_fs_server_backend>(t.log(), root);
			});
	});
```

### Trying it out

The example server serves a directory over SFTP and works with the standard OpenSSH client:

```sh
./bin/spssh_test_server -p 2222 -b 127.0.0.1 --private-key tools/keys/ed25519_test_key --sftp-root /some/dir
sftp -P 2222 -i tools/keys/ed25519_test_key test@127.0.0.1
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

## Testing

Unit tests (Catch2) cover the transport, key exchange, authentication, connection and SFTP
layers, including end-to-end client/server tests over the full protocol stack:

```sh
./bin/test_spssh "[unit]"   # the whole suite
./bin/test_spssh "[sftp]"   # sftp only
```

CI builds and runs the tests with GCC and Clang on Linux and MSVC on Windows.

## License

See [LICENSE](LICENSE).
