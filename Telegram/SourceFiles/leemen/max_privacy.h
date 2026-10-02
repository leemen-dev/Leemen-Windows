#pragma once

#include "leemen/sync_crypto.h"

namespace Leemen::Sync {

inline constexpr auto kRecoveryEntropyBytes = std::size_t(16);
inline constexpr auto kRecoveryWordCount = std::size_t(12);

struct PasswordWrapping {
	WrappedKey wrapped = {};
	Salt salt = {};
};

struct MaximumPrivacySetup {
	PasswordWrapping password;
	PasswordWrapping recovery;
	SecretBytes recoveryPhrase;
};

[[nodiscard]] std::optional<SecretBytes> RecoveryPhraseFromEntropy(
	std::span<const unsigned char> entropy);
[[nodiscard]] std::optional<SecretBytes> GenerateRecoveryPhrase();
[[nodiscard]] std::optional<SecretBytes> NormalizeRecoveryPhrase(std::string_view phrase);
[[nodiscard]] bool IsValidRecoveryPhrase(std::string_view phrase);
[[nodiscard]] std::optional<PasswordWrapping> PreparePasswordWrapping(
	std::span<const unsigned char> masterKey,
	std::string_view passphrase);
[[nodiscard]] std::optional<MaximumPrivacySetup> PrepareMaximumPrivacy(
	std::span<const unsigned char> masterKey,
	std::string_view passphrase);

} // namespace Leemen::Sync
