
#include "crypto.hpp"

namespace securepath::ssh::test {

ssh_private_key crypto_test_context::test_ed25519_private_key() const {
	return load_raw_base64_ssh_private_key(
		"AAAAC3NzaC1lZDI1NTE5AAAAIKybvEDG+Tp2x91UjeDAFwmeOfitihW8fKN4rzMf2DBnAAAAQEee9Mvoputz204F1EtY51yPsLFm10kpJOw1tMVVyZT2rJu8QMb5OnbH3VSN4MAXCZ45+K2KFbx8o3ivMx/YMGcAAAARbWlrYWVsQG1pa2FlbC1kZXYBAgME",
		*this, call);
}

}

