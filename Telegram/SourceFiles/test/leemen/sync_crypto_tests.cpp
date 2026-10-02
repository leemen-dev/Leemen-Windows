#include "leemen/sync_crypto.h"
#include "test/leemen/sync_crypto_vectors.h"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <sodium.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace {

using namespace Leemen::Sync;

auto Checks = 0;
auto OpenSslChecksSkipped = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

std::span<const unsigned char> Bytes(std::string_view value) {
	return { reinterpret_cast<const unsigned char*>(value.data()), value.size() };
}

bool Equal(
		std::span<const unsigned char> a,
		std::span<const unsigned char> b) {
	return std::ranges::equal(a, b);
}

std::optional<SecretKey> OpenSslArgon2(
		std::string_view secret,
		Salt salt,
		unsigned int operations) {
	auto algorithm = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>(
		EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr), EVP_KDF_free);
	if (!algorithm) {
		return std::nullopt;
	}
	auto context = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>(
		EVP_KDF_CTX_new(algorithm.get()), EVP_KDF_CTX_free);
	Check(context != nullptr, "OpenSSL Argon2id context available");
	auto memoryKiB = 65536U;
	auto lanes = 1U;
	auto threads = 1U;
	auto version = 0x13U;
	auto cleanse = 1U;
	auto password = SecretBytes(secret.size());
	std::ranges::copy(Bytes(secret), password.bytes().begin());
	auto params = std::array{
		OSSL_PARAM_construct_octet_string(
			OSSL_KDF_PARAM_PASSWORD, password.bytes().data(), password.bytes().size()),
		OSSL_PARAM_construct_octet_string(
			OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
		OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &operations),
		OSSL_PARAM_construct_uint("memcost", &memoryKiB),
		OSSL_PARAM_construct_uint("lanes", &lanes),
		OSSL_PARAM_construct_uint("threads", &threads),
		OSSL_PARAM_construct_uint("version", &version),
		OSSL_PARAM_construct_uint("early_clean", &cleanse),
		OSSL_PARAM_construct_end(),
	};
	auto result = SecretKey();
	Check(EVP_KDF_derive(
		context.get(), result.bytes().data(), kKeyBytes, params.data()) == 1,
		"independent OpenSSL Argon2id derivation");
	return result;
}

void CheckOpenSslVector(
		std::string_view secret,
		Salt salt,
		unsigned int operations,
		std::span<const unsigned char> expected) {
	const auto derived = OpenSslArgon2(secret, salt, operations);
	if (!derived) {
		++OpenSslChecksSkipped;
		return;
	}
	Check(Equal(derived->bytes(), expected), "independent OpenSSL Argon2id comparison");
}

void TestKnownAeadVector() {
	const auto plaintext = OpenBlob(kCiphertext, kVectorNonce, kVectorKey);
	Check(plaintext.has_value(), "open upstream libsodium no-AAD vector");
	Check(Equal(plaintext->bytes(), Bytes(kVectorMessage)), "vector plaintext exact");
	Check(!OpenBlob(kCiphertextWithAad, kVectorNonce, kVectorKey),
		"reject vector authenticated with nonempty AAD");

	for (auto index = std::size_t(0); index < kCiphertext.size(); ++index) {
		auto corrupt = kCiphertext;
		corrupt[index] ^= 1;
		Check(!OpenBlob(corrupt, kVectorNonce, kVectorKey),
			"reject every ciphertext and tag byte mutation");
	}
	for (auto index = std::size_t(0); index < kVectorNonce.size(); ++index) {
		auto nonce = kVectorNonce;
		nonce[index] ^= 1;
		Check(!OpenBlob(kCiphertext, nonce, kVectorKey), "reject nonce mutation");
	}
	auto wrongKey = kVectorKey;
	wrongKey.back() ^= 1;
	Check(!OpenBlob(kCiphertext, kVectorNonce, wrongKey), "reject wrong AEAD key");
}

void TestAeadRoundTrip() {
	const auto first = SealBlob(Bytes(kVectorMessage), kVectorKey);
	const auto second = SealBlob(Bytes(kVectorMessage), kVectorKey);
	Check(first && second, "seal repeated message");
	Check(first->nonce != second->nonce, "fresh random nonces");
	Check(first->ciphertext != second->ciphertext, "nonce changes ciphertext");
	Check(first->ciphertext.size() == kVectorMessage.size() + kTagBytes,
		"ciphertext includes exactly one tag");
	auto reference = SecretBytes(kVectorMessage.size());
	auto length = 0ULL;
	Check(crypto_aead_xchacha20poly1305_ietf_decrypt(
		reference.bytes().data(), &length, nullptr,
		first->ciphertext.data(), first->ciphertext.size(), nullptr, 0,
		first->nonce.data(), kVectorKey.data()) == 0,
		"sealed bytes open through direct Android-equivalent libsodium API");
	Check(length == kVectorMessage.size()
		&& Equal(reference.bytes(), Bytes(kVectorMessage)), "reference plaintext exact");

	const auto empty = SealBlob({}, kVectorKey);
	Check(empty && empty->ciphertext.size() == kTagBytes, "empty plaintext tag");
	const auto opened = OpenBlob(empty->ciphertext, empty->nonce, kVectorKey);
	Check(opened && opened->bytes().empty(), "empty plaintext roundtrip");
	const auto binary = std::string_view("\0\xff\x80hello\0", 10);
	const auto binarySealed = SealBlob(Bytes(binary), kVectorKey);
	Check(binarySealed.has_value(), "seal binary data");
	const auto binaryOpened = OpenBlob(
		binarySealed->ciphertext, binarySealed->nonce, kVectorKey);
	Check(binaryOpened && Equal(binaryOpened->bytes(), Bytes(binary)),
		"binary plaintext exact including NUL");
}

void TestBounds() {
	for (const auto size : { 0U, 1U, 15U, 16U, 24U, 31U, 33U }) {
		const auto key = std::vector<unsigned char>(size);
		Check(!SealBlob({}, key), "reject malformed seal key size");
		Check(!OpenBlob(kCiphertext, kVectorNonce, key), "reject malformed open key size");
		Check(!WrapMasterKey(key, kVectorKey), "reject malformed master key size");
		Check(!WrapMasterKey(kVectorKey, key), "reject malformed wrapping key size");
	}
	for (const auto size : { 0U, 8U, 16U, 23U, 25U, 32U }) {
		const auto nonce = std::vector<unsigned char>(size);
		Check(!OpenBlob(kCiphertext, nonce, kVectorKey), "reject malformed nonce size");
	}
	for (auto size = std::size_t(0); size < kTagBytes; ++size) {
		const auto ciphertext = std::vector<unsigned char>(size);
		Check(!OpenBlob(ciphertext, kVectorNonce, kVectorKey), "reject truncated tag");
	}
	const auto oversized = std::vector<unsigned char>(kMaxCiphertextBytes + 1);
	Check(!OpenBlob(oversized, kVectorNonce, kVectorKey), "bound wire allocation");
	Check(!SealBlob(oversized, kVectorKey), "bound plaintext allocation");
	const auto maxPlaintext = std::vector<unsigned char>(
		kMaxCiphertextBytes - kTagBytes, 0xa5);
	const auto maxSealed = SealBlob(maxPlaintext, kVectorKey);
	Check(maxSealed && maxSealed->ciphertext.size() == kMaxCiphertextBytes,
		"accept exact backend ciphertext limit");
	const auto maxOpened = OpenBlob(maxSealed->ciphertext, maxSealed->nonce, kVectorKey);
	Check(maxOpened && Equal(maxOpened->bytes(), maxPlaintext), "maximum blob roundtrip");
	Check(!SealBlob(std::span(oversized).first(maxPlaintext.size() + 1), kVectorKey),
		"reject one byte above plaintext limit");

	for (const auto size : { 0U, 15U, 17U, 32U }) {
		const auto salt = std::vector<unsigned char>(size);
		Check(!DerivePinHash("246810", salt), "reject malformed PIN salt");
		Check(!DeriveWrappingKey("secret", salt), "reject malformed KEK salt");
	}
	for (const auto size : { 0U, 16U, 31U, 33U }) {
		const auto digest = std::vector<unsigned char>(size);
		Check(!VerifySyncedPin("246810", kKdfSalt, digest), "reject malformed PIN hash");
	}
	for (const auto &secret : { std::string(), std::string(kMaxSecretBytes + 1, 'x') }) {
		Check(!DerivePinHash(secret, kKdfSalt), "reject empty or oversized PIN");
		Check(!DeriveWrappingKey(secret, kKdfSalt), "reject empty or oversized secret");
	}
	const auto maxSecret = std::string(kMaxSecretBytes, 'x');
	const auto maxDerived = DerivePinHash(maxSecret, kKdfSalt);
	Check(maxDerived.has_value(), "accept exact secret bound without truncation");
	CheckOpenSslVector(maxSecret, kKdfSalt, 2, maxDerived->bytes());
}

void TestPinAndWrappingKdf() {
	const auto pin = DerivePinHash("246810", kKdfSalt);
	Check(pin && Equal(pin->bytes(), kPinDigest), "fixed Argon2id interactive vector");
	const auto kek = DeriveWrappingKey(kWrappingSecret, kKdfSalt);
	Check(kek && Equal(kek->bytes(), kWrappingDigest), "fixed Argon2id KEK vector");
	CheckOpenSslVector("246810", kKdfSalt, 2, kPinDigest);
	CheckOpenSslVector(kWrappingSecret, kKdfSalt, 4, kWrappingDigest);
	Check(VerifySyncedPin("246810", kKdfSalt, kPinDigest), "verify synced PIN");
	Check(!VerifySyncedPin("246811", kKdfSalt, kPinDigest), "reject wrong synced PIN");
	auto corruptDigest = kPinDigest;
	corruptDigest.front() ^= 1;
	Check(!VerifySyncedPin("246810", kKdfSalt, corruptDigest), "reject corrupt PIN hash");
	auto wrongSalt = kKdfSalt;
	wrongSalt.back() ^= 1;
	Check(!VerifySyncedPin("246810", wrongSalt, kPinDigest), "reject wrong PIN salt");

	// Java passes the UTF-8 array length, including NUL; no ASCII or normalization policy here.
	const auto binarySecret = std::string_view("p\xc3\xa4ss\0\xe5\xaf\x86", 9);
	const auto binaryHash = DerivePinHash(binarySecret, kKdfSalt);
	Check(binaryHash.has_value(), "accept exact UTF-8 and embedded NUL bytes");
	CheckOpenSslVector(binarySecret, kKdfSalt, 2, binaryHash->bytes());
	const auto firstSalt = RandomSalt();
	const auto secondSalt = RandomSalt();
	Check(firstSalt && secondSalt && *firstSalt != *secondSalt, "fresh random salts");
	const auto firstHash = DerivePinHash("246810", *firstSalt);
	Check(firstHash && !Equal(firstHash->bytes(), pin->bytes()), "random salt changes hash");
}

void TestKeyWrap() {
	const auto kek = DeriveWrappingKey(kWrappingSecret, kKdfSalt);
	const auto wrongKek = DeriveWrappingKey("wrong wrapping secret", kKdfSalt);
	Check(kek && wrongKek, "derive independent wrapping keys");
	const auto wrapped = WrapMasterKey(kVectorKey, kek->bytes());
	const auto second = WrapMasterKey(kVectorKey, kek->bytes());
	Check(wrapped && second && *wrapped != *second, "random self-contained 72-byte wrap");
	const auto unwrapped = UnwrapMasterKey(*wrapped, kek->bytes());
	Check(unwrapped && Equal(unwrapped->bytes(), kVectorKey), "master key roundtrip");
	Check(!UnwrapMasterKey(*wrapped, wrongKek->bytes()), "reject wrong wrapping secret");
	const auto direct = OpenBlob(
		std::span(*wrapped).subspan(kNonceBytes),
		std::span(*wrapped).first(kNonceBytes), kek->bytes());
	Check(direct && Equal(direct->bytes(), kVectorKey), "Android nonce-ciphertext-tag layout");
	for (auto index = std::size_t(0); index < wrapped->size(); ++index) {
		auto corrupt = *wrapped;
		corrupt[index] ^= 1;
		Check(!UnwrapMasterKey(corrupt, kek->bytes()), "reject every wrap byte mutation");
	}
	for (const auto size : { 0U, 24U, 40U, 71U, 73U, 128U }) {
		const auto invalid = std::vector<unsigned char>(size);
		Check(!UnwrapMasterKey(invalid, kek->bytes()), "reject malformed wrap size");
	}
	Check(!UnwrapMasterKey(*wrapped, {}), "reject missing wrapping key");
}

void TestSecretOwnership() {
	static_assert(!std::is_copy_constructible_v<SecretKey>);
	static_assert(!std::is_copy_assignable_v<SecretKey>);
	static_assert(!std::is_copy_constructible_v<SecretBytes>);
	static_assert(!std::is_copy_assignable_v<SecretBytes>);
	static_assert(std::is_nothrow_move_constructible_v<SecretKey>);
	static_assert(std::is_nothrow_move_constructible_v<SecretBytes>);
	auto key = SecretKey();
	std::ranges::copy(kVectorKey, key.bytes().begin());
	auto moved = SecretKey(std::move(key));
	Check(Equal(moved.bytes(), kVectorKey), "move transfers key");
	Check(std::ranges::all_of(key.bytes(), [](auto byte) { return byte == 0; }),
		"move clears source key");
	key = std::move(moved);
	Check(Equal(key.bytes(), kVectorKey), "move assignment transfers key");
	Check(std::ranges::all_of(moved.bytes(), [](auto byte) { return byte == 0; }),
		"move assignment clears source key");
	key.clear();
	Check(std::ranges::all_of(key.bytes(), [](auto byte) { return byte == 0; }),
		"explicit key clear zeroes buffer");
	auto bytes = SecretBytes(kVectorKey.size());
	std::ranges::copy(kVectorKey, bytes.bytes().begin());
	auto movedBytes = SecretBytes(std::move(bytes));
	Check(Equal(movedBytes.bytes(), kVectorKey), "move transfers plaintext");
	bytes = std::move(movedBytes);
	Check(Equal(bytes.bytes(), kVectorKey), "move assignment transfers plaintext");
	bytes.clear();
	Check(bytes.bytes().empty(), "clear removes plaintext access");
	const auto first = RandomKey();
	const auto second = RandomKey();
	Check(first && second && !Equal(first->bytes(), second->bytes()), "fresh random keys");
}

} // namespace

int main() {
	Check(sodium_init() >= 0, "libsodium initialization");
	TestKnownAeadVector();
	TestAeadRoundTrip();
	TestBounds();
	TestPinAndWrappingKdf();
	TestKeyWrap();
	TestSecretOwnership();
	std::cout << "Sync crypto checks passed: " << Checks << '\n';
	if (OpenSslChecksSkipped) {
		std::cout << "Optional OpenSSL Argon2id oracle unavailable: "
			<< OpenSslChecksSkipped << " comparisons skipped; fixed vectors executed.\n";
	}
}
