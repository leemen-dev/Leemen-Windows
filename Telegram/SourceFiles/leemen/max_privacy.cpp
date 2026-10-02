#include "leemen/max_privacy.h"

#include "leemen/bip39_english.h"

#include <openssl/evp.h>

#include <algorithm>
#include <utility>

namespace Leemen::Sync {
namespace {

std::string_view View(const SecretBytes &bytes) {
	return { reinterpret_cast<const char*>(bytes.bytes().data()), bytes.bytes().size() };
}

std::optional<SecretKey> EntropyDigest(std::span<const unsigned char> entropy) {
	auto result = SecretKey();
	auto written = 0U;
	if (EVP_Digest(
			entropy.data(),
			entropy.size(),
			result.bytes().data(),
			&written,
			EVP_sha256(),
			nullptr) != 1
		|| written != kKeyBytes) {
		return std::nullopt;
	}
	return result;
}

bool IsJavaWhitespace(unsigned char value) {
	return value == ' ' || (value >= '\t' && value <= '\r');
}

std::optional<SecretBytes> Normalize(std::string_view phrase) {
	if (phrase.empty() || phrase.size() > kMaxSecretBytes) {
		return std::nullopt;
	}
	while (!phrase.empty() && static_cast<unsigned char>(phrase.front()) <= 0x20) {
		phrase.remove_prefix(1);
	}
	while (!phrase.empty() && static_cast<unsigned char>(phrase.back()) <= 0x20) {
		phrase.remove_suffix(1);
	}
	if (phrase.empty()) {
		return std::nullopt;
	}
	auto buffer = SecretBytes(phrase.size());
	auto used = std::size_t(0);
	for (auto i = std::size_t(0); i < phrase.size(); ++i) {
		auto value = static_cast<unsigned char>(phrase[i]);
		if (IsJavaWhitespace(value)) {
			if (used > 0 && buffer.bytes()[used - 1] != ' ') {
				buffer.bytes()[used++] = ' ';
			}
			continue;
		}
		if (value >= 'A' && value <= 'Z') {
			value += 'a' - 'A';
		} else if (phrase.substr(i, 3) == "\xe2\x84\xaa") {
			value = 'k';
			i += 2;
		}
		if (value < 'a' || value > 'z') {
			return std::nullopt;
		}
		buffer.bytes()[used++] = value;
	}
	auto result = SecretBytes(used);
	std::ranges::copy(buffer.bytes().first(used), result.bytes().begin());
	return result;
}

bool ValidCanonicalPhrase(std::string_view phrase) {
	auto entropy = SecretBytes(kRecoveryEntropyBytes + 1);
	auto offset = std::size_t(0);
	for (auto word = std::size_t(0); word < kRecoveryWordCount; ++word) {
		const auto end = phrase.find(' ', offset);
		if ((word + 1 == kRecoveryWordCount) != (end == std::string_view::npos)) {
			return false;
		}
		const auto value = phrase.substr(offset, end == std::string_view::npos
			? std::string_view::npos : end - offset);
		const auto found = std::ranges::lower_bound(Details::kBip39EnglishWords, value);
		if (found == Details::kBip39EnglishWords.end() || *found != value) {
			return false;
		}
		const auto index = static_cast<unsigned int>(found - Details::kBip39EnglishWords.begin());
		for (auto bit = std::size_t(0); bit < 11; ++bit) {
			const auto position = word * 11 + bit;
			entropy.bytes()[position / 8] |= static_cast<unsigned char>(
				((index >> (10 - bit)) & 1) << (7 - position % 8));
		}
		if (end != std::string_view::npos) {
			offset = end + 1;
		}
	}
	const auto digest = EntropyDigest(entropy.bytes().first(kRecoveryEntropyBytes));
	return digest && (entropy.bytes()[kRecoveryEntropyBytes] >> 4) == (digest->bytes()[0] >> 4);
}

} // namespace

std::optional<SecretBytes> RecoveryPhraseFromEntropy(std::span<const unsigned char> entropy) {
	if (entropy.size() != kRecoveryEntropyBytes) {
		return std::nullopt;
	}
	const auto digest = EntropyDigest(entropy);
	if (!digest) {
		return std::nullopt;
	}
	auto buffer = SecretBytes(kRecoveryWordCount * 9);
	auto used = std::size_t(0);
	for (auto word = std::size_t(0); word < kRecoveryWordCount; ++word) {
		auto index = std::size_t(0);
		for (auto bit = std::size_t(0); bit < 11; ++bit) {
			const auto position = word * 11 + bit;
			const auto byte = (position < 128) ? entropy[position / 8] : digest->bytes()[0];
			index = (index << 1) | ((byte >> (7 - position % 8)) & 1);
		}
		if (word != 0) {
			buffer.bytes()[used++] = ' ';
		}
		const auto value = Details::kBip39EnglishWords[index];
		std::ranges::copy(value, buffer.bytes().begin() + used);
		used += value.size();
	}
	auto result = SecretBytes(used);
	std::ranges::copy(buffer.bytes().first(used), result.bytes().begin());
	return result;
}

std::optional<SecretBytes> GenerateRecoveryPhrase() {
	const auto entropy = RandomKey();
	return entropy ? RecoveryPhraseFromEntropy(entropy->bytes().first(kRecoveryEntropyBytes)) : std::nullopt;
}

std::optional<SecretBytes> NormalizeRecoveryPhrase(std::string_view phrase) {
	auto normalized = Normalize(phrase);
	return (normalized && ValidCanonicalPhrase(View(*normalized)))
		? std::move(normalized)
		: std::nullopt;
}

bool IsValidRecoveryPhrase(std::string_view phrase) {
	return NormalizeRecoveryPhrase(phrase).has_value();
}

std::optional<PasswordWrapping> PreparePasswordWrapping(
		std::span<const unsigned char> masterKey,
		std::string_view passphrase) {
	if (masterKey.size() != kKeyBytes || passphrase.empty() || passphrase.size() > kMaxSecretBytes) {
		return std::nullopt;
	}
	const auto salt = RandomSalt();
	const auto key = salt ? DeriveWrappingKey(passphrase, *salt) : std::nullopt;
	const auto wrapped = key ? WrapMasterKey(masterKey, key->bytes()) : std::nullopt;
	return wrapped ? std::make_optional(PasswordWrapping{ *wrapped, *salt }) : std::nullopt;
}

std::optional<MaximumPrivacySetup> PrepareMaximumPrivacy(
		std::span<const unsigned char> masterKey,
		std::string_view passphrase) {
	if (masterKey.size() != kKeyBytes || passphrase.empty() || passphrase.size() > kMaxSecretBytes) {
		return std::nullopt;
	}
	auto phrase = GenerateRecoveryPhrase();
	if (!phrase) {
		return std::nullopt;
	}
	const auto password = PreparePasswordWrapping(masterKey, passphrase);
	const auto recovery = PreparePasswordWrapping(masterKey, View(*phrase));
	if (!password || !recovery) {
		return std::nullopt;
	}
	return MaximumPrivacySetup{ *password, *recovery, std::move(*phrase) };
}

} // namespace Leemen::Sync
