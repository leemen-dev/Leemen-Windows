#include "leemen/max_privacy.h"
#include "leemen/bip39_english.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <type_traits>

namespace {

using namespace Leemen::Sync;
auto Checks = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

std::string_view View(const SecretBytes &bytes) {
	return { reinterpret_cast<const char*>(bytes.bytes().data()), bytes.bytes().size() };
}

std::string Hex(std::span<const unsigned char> bytes) {
	auto result = std::string();
	for (const auto byte : bytes) {
		result.push_back("0123456789abcdef"[byte >> 4]);
		result.push_back("0123456789abcdef"[byte & 15]);
	}
	return result;
}

void MnemonicTests() {
	// Official public BIP-39 vectors: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
	const auto fixtures = std::array<std::pair<unsigned char, std::string_view>, 4>{ {
		{ 0x00, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
		{ 0x7f, "legal winner thank year wave sausage worth useful legal winner thank yellow" },
		{ 0x80, "letter advice cage absurd amount doctor acoustic avoid letter advice cage above" },
		{ 0xff, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong" },
	} };
	for (const auto &[byte, expected] : fixtures) {
		auto entropy = std::array<unsigned char, kRecoveryEntropyBytes>();
		entropy.fill(byte);
		const auto phrase = RecoveryPhraseFromEntropy(entropy);
		Check(phrase && View(*phrase) == expected, "official entropy-to-mnemonic vector");
		Check(IsValidRecoveryPhrase(expected), "official mnemonic validates checksum");
		auto upper = std::string("\x01\t");
		for (const auto ch : expected) {
			if (ch == ' ') upper += " \t\n\v\f\r";
			else upper.push_back(static_cast<char>(ch - 'a' + 'A'));
		}
		upper += " \r\x02";
		const auto normalized = NormalizeRecoveryPhrase(upper);
		Check(normalized && View(*normalized) == expected, "Java trim lowercase and ASCII whitespace normalization");
	}
	auto kelvin = std::string(fixtures[1].second);
	kelvin.replace(kelvin.find('k'), 1, "\xe2\x84\xaa");
	const auto normalizedKelvin = NormalizeRecoveryPhrase(kelvin);
	Check(normalizedKelvin && View(*normalizedKelvin) == fixtures[1].second, "Java lowercase Kelvin sign compatibility");
	const auto invalid = std::array<std::string_view, 9>{
		"", " \t\n\r\v\f", "abandon", "not-a-mnemonic", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abou",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"абандон abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	};
	for (const auto phrase : invalid) {
		Check(!IsValidRecoveryPhrase(phrase), "invalid phrase rejected");
		Check(!NormalizeRecoveryPhrase(phrase), "normalization cannot accept invalid word count or checksum");
	}
	for (const auto &whitespace : { std::string("\xc2\xa0"), std::string("\xe2\x80\x83"), std::string(1, '\0'), std::string(1, '\x1f') }) {
		auto candidate = std::string(fixtures[0].second);
		candidate.replace(candidate.find(' '), 1, whitespace);
		Check(!IsValidRecoveryPhrase(candidate), "Java regex does not collapse Unicode whitespace or interior control bytes");
	}
	Check(!NormalizeRecoveryPhrase(std::string(kMaxSecretBytes + 1, ' ')), "untrusted input allocation bounded");
	for (const auto size : { 0U, 1U, 15U, 17U, 24U, 32U }) {
		Check(!RecoveryPhraseFromEntropy(std::vector<unsigned char>(size)), "Android supports only 128-bit entropy");
	}
	auto joined = std::string();
	for (const auto word : Details::kBip39EnglishWords) {
		joined += word;
		joined += '\n';
	}
	auto digest = std::array<unsigned char, 32>();
	auto written = 0U;
	Check(EVP_Digest(joined.data(), joined.size(), digest.data(), &written, EVP_sha256(), nullptr) == 1,
		"hash canonical public word list");
	Check(Hex(digest) == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
		"word list exact Android iOS and canonical BIP-39 source hash");
	Check(std::ranges::is_sorted(Details::kBip39EnglishWords), "word list sorted for binary search");
	auto seen = std::set<std::string>();
	for (auto i = 0; i != 32; ++i) {
		const auto phrase = GenerateRecoveryPhrase();
		Check(phrase && IsValidRecoveryPhrase(View(*phrase)), "secure random phrase valid");
		Check(seen.insert(std::string(View(*phrase))).second, "fresh random recovery entropy");
	}
}

void WrappingTests() {
	static_assert(!std::is_copy_constructible_v<MaximumPrivacySetup>);
	static_assert(std::is_move_constructible_v<MaximumPrivacySetup>);
	auto master = std::array<unsigned char, kKeyBytes>();
	for (auto i = std::size_t(0); i < master.size(); ++i) master[i] = static_cast<unsigned char>(i);
	const auto passphrase = std::string_view("  Leemen public тест fixture  ");
	auto setup = PrepareMaximumPrivacy(master, passphrase);
	Check(setup.has_value(), "maximum privacy preparation succeeds");
	Check(IsValidRecoveryPhrase(View(setup->recoveryPhrase)), "setup carries valid recovery phrase");
	Check(setup->password.salt != setup->recovery.salt, "password and recovery salts independent");
	Check(setup->password.wrapped != setup->recovery.wrapped, "password and recovery ciphertext distinct");
	const auto passwordKey = DeriveWrappingKey(passphrase, setup->password.salt);
	const auto recoveryKey = DeriveWrappingKey(View(setup->recoveryPhrase), setup->recovery.salt);
	Check(passwordKey && recoveryKey, "both wrapping keys derive with Android Argon2id profile");
	const auto passwordMaster = UnwrapMasterKey(setup->password.wrapped, passwordKey->bytes());
	const auto recoveryMaster = UnwrapMasterKey(setup->recovery.wrapped, recoveryKey->bytes());
	Check(passwordMaster && std::ranges::equal(passwordMaster->bytes(), master), "password unwrap preserves original master key");
	Check(recoveryMaster && std::ranges::equal(recoveryMaster->bytes(), master), "recovery unwrap preserves original master key");
	const auto trimmedKey = DeriveWrappingKey("Leemen public тест fixture", setup->password.salt);
	Check(trimmedKey && !UnwrapMasterKey(setup->password.wrapped, trimmedKey->bytes()), "everyday passphrase must never be normalized");
	Check(!UnwrapMasterKey(setup->recovery.wrapped, passwordKey->bytes()), "password leg cannot unlock recovery leg");
	auto tampered = setup->recovery.wrapped;
	tampered.back() ^= 1;
	Check(!UnwrapMasterKey(tampered, recoveryKey->bytes()), "tampered recovery wrap rejected");
	const auto rewrap = PreparePasswordWrapping(master, "replacement public fixture");
	Check(rewrap && rewrap->salt != setup->password.salt, "rewrap generates fresh salt");
	const auto replacementKey = DeriveWrappingKey("replacement public fixture", rewrap->salt);
	const auto replacementMaster = replacementKey ? UnwrapMasterKey(rewrap->wrapped, replacementKey->bytes()) : std::nullopt;
	Check(replacementMaster && std::ranges::equal(replacementMaster->bytes(), master), "password rewrap preserves same master");
	Check(UnwrapMasterKey(setup->recovery.wrapped, recoveryKey->bytes()).has_value(), "rewrap leaves recovery wrapper usable");
	for (const auto &invalid : { std::string(), std::string(kMaxSecretBytes + 1, 'x') }) {
		Check(!PrepareMaximumPrivacy(master, invalid), "setup rejects empty or oversized password");
		Check(!PreparePasswordWrapping(master, invalid), "rewrap rejects empty or oversized password");
	}
	Check(!PrepareMaximumPrivacy({}, passphrase), "setup requires loaded master key");
	Check(!PreparePasswordWrapping({}, passphrase), "rewrap requires loaded master key");
}

} // namespace

int main() {
	MnemonicTests();
	WrappingTests();
	std::cout << "Maximum privacy checks passed: " << Checks << '\n';
}
