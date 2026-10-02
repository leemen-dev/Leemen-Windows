#pragma once

#include <array>
#include <optional>
#include <string_view>

namespace Leemen {

// Local v1 PBKDF2 verifier; incompatible with Android's synced Argon2id PIN.
struct LocalPin {
	std::array<unsigned char, 16> salt = {};
	std::array<unsigned char, 32> digest = {};
};

[[nodiscard]] std::optional<LocalPin> CreateLocalPin(std::string_view pin);
[[nodiscard]] bool VerifyLocalPin(std::string_view pin, const LocalPin &stored);

} // namespace Leemen
