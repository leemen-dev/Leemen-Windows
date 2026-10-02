#include "leemen/sync_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sodium.h>

#include <algorithm>
#include <utility>

namespace Leemen::Sync {
namespace {

constexpr auto kPinOperations = 2ULL;
constexpr auto kWrappingOperations = 4ULL;
constexpr auto kKdfMemoryBytes = std::size_t(64 * 1024 * 1024);

static_assert(kKeyBytes == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(kNonceBytes == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(kTagBytes == crypto_aead_xchacha20poly1305_ietf_ABYTES);
static_assert(kSaltBytes == crypto_pwhash_SALTBYTES);

bool Initialized() {
	static const auto result = (sodium_init() >= 0);
	return result;
}

bool FillRandom(std::span<unsigned char> bytes) {
	return RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) == 1;
}

std::optional<SecretKey> DeriveKey(
		std::string_view secret,
		std::span<const unsigned char> salt,
		unsigned long long operations) {
	if (secret.empty()
		|| secret.size() > kMaxSecretBytes
		|| salt.size() != kSaltBytes
		|| !Initialized()) {
		return std::nullopt;
	}
	auto result = SecretKey();
	if (crypto_pwhash(
			result.bytes().data(),
			kKeyBytes,
			secret.data(),
			secret.size(),
			salt.data(),
			operations,
			kKdfMemoryBytes,
			crypto_pwhash_ALG_ARGON2ID13) != 0) {
		return std::nullopt;
	}
	return result;
}

} // namespace

SecretKey::SecretKey(SecretKey &&other) noexcept : _bytes(other._bytes) {
	other.clear();
}

SecretKey &SecretKey::operator=(SecretKey &&other) noexcept {
	if (this != &other) {
		clear();
		_bytes = other._bytes;
		other.clear();
	}
	return *this;
}

SecretKey::~SecretKey() {
	clear();
}

std::span<unsigned char, kKeyBytes> SecretKey::bytes() {
	return _bytes;
}

std::span<const unsigned char, kKeyBytes> SecretKey::bytes() const {
	return _bytes;
}

void SecretKey::clear() noexcept {
	OPENSSL_cleanse(_bytes.data(), _bytes.size());
}

SecretBytes::SecretBytes(std::size_t size) : _bytes(size) {
}

SecretBytes::SecretBytes(SecretBytes &&other) noexcept
: _bytes(std::move(other._bytes)) {
}

SecretBytes &SecretBytes::operator=(SecretBytes &&other) noexcept {
	if (this != &other) {
		clear();
		_bytes = std::move(other._bytes);
	}
	return *this;
}

SecretBytes::~SecretBytes() {
	clear();
}

std::span<unsigned char> SecretBytes::bytes() {
	return _bytes;
}

std::span<const unsigned char> SecretBytes::bytes() const {
	return _bytes;
}

void SecretBytes::clear() noexcept {
	if (!_bytes.empty()) {
		OPENSSL_cleanse(_bytes.data(), _bytes.size());
		_bytes.clear();
	}
}

std::optional<SecretKey> RandomKey() {
	auto result = SecretKey();
	return FillRandom(result.bytes())
		? std::make_optional(std::move(result))
		: std::nullopt;
}

std::optional<Salt> RandomSalt() {
	auto result = Salt();
	return FillRandom(result) ? std::make_optional(result) : std::nullopt;
}

std::optional<std::array<unsigned char, kKeyBytes>> MasterKeyFingerprint(
		std::span<const unsigned char> key) {
	if (key.size() != kKeyBytes) {
		return std::nullopt;
	}
	auto result = std::array<unsigned char, kKeyBytes>();
	auto written = 0U;
	if (EVP_Digest(
			key.data(),
			key.size(),
			result.data(),
			&written,
			EVP_sha256(),
			nullptr) != 1
		|| written != result.size()) {
		return std::nullopt;
	}
	return result;
}

std::optional<EncryptedBlob> SealBlob(
		std::span<const unsigned char> plaintext,
		std::span<const unsigned char> key) {
	if (key.size() != kKeyBytes
		|| plaintext.size() > kMaxCiphertextBytes - kTagBytes
		|| !Initialized()) {
		return std::nullopt;
	}
	auto result = EncryptedBlob();
	if (!FillRandom(result.nonce)) {
		return std::nullopt;
	}
	result.ciphertext.resize(plaintext.size() + kTagBytes);
	auto written = 0ULL;
	if (crypto_aead_xchacha20poly1305_ietf_encrypt(
			result.ciphertext.data(),
			&written,
			plaintext.data(),
			plaintext.size(),
			nullptr,
			0,
			nullptr,
			result.nonce.data(),
			key.data()) != 0
		|| written != result.ciphertext.size()) {
		return std::nullopt;
	}
	return result;
}

std::optional<SecretBytes> OpenBlob(
		std::span<const unsigned char> ciphertext,
		std::span<const unsigned char> nonce,
		std::span<const unsigned char> key) {
	if (key.size() != kKeyBytes
		|| nonce.size() != kNonceBytes
		|| ciphertext.size() < kTagBytes
		|| ciphertext.size() > kMaxCiphertextBytes
		|| !Initialized()) {
		return std::nullopt;
	}
	auto result = SecretBytes(ciphertext.size() - kTagBytes);
	auto written = 0ULL;
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(
			result.bytes().data(),
			&written,
			nullptr,
			ciphertext.data(),
			ciphertext.size(),
			nullptr,
			0,
			nonce.data(),
			key.data()) != 0
		|| written != result.bytes().size()) {
		return std::nullopt;
	}
	return result;
}

std::optional<SecretKey> DerivePinHash(
		std::string_view pin,
		std::span<const unsigned char> salt) {
	return DeriveKey(pin, salt, kPinOperations);
}

bool VerifySyncedPin(
		std::string_view pin,
		std::span<const unsigned char> salt,
		std::span<const unsigned char> digest) {
	if (digest.size() != kKeyBytes) {
		return false;
	}
	const auto derived = DerivePinHash(pin, salt);
	return derived
		&& CRYPTO_memcmp(
			derived->bytes().data(),
			digest.data(),
			kKeyBytes) == 0;
}

std::optional<SecretKey> DeriveWrappingKey(
		std::string_view secret,
		std::span<const unsigned char> salt) {
	return DeriveKey(secret, salt, kWrappingOperations);
}

std::optional<WrappedKey> WrapMasterKey(
		std::span<const unsigned char> masterKey,
		std::span<const unsigned char> wrappingKey) {
	if (masterKey.size() != kKeyBytes) {
		return std::nullopt;
	}
	const auto blob = SealBlob(masterKey, wrappingKey);
	if (!blob) {
		return std::nullopt;
	}
	auto result = WrappedKey();
	std::copy(blob->nonce.begin(), blob->nonce.end(), result.begin());
	std::copy(
		blob->ciphertext.begin(),
		blob->ciphertext.end(),
		result.begin() + kNonceBytes);
	return result;
}

std::optional<SecretKey> UnwrapMasterKey(
		std::span<const unsigned char> wrapped,
		std::span<const unsigned char> wrappingKey) {
	if (wrapped.size() != kWrappedKeyBytes) {
		return std::nullopt;
	}
	const auto plaintext = OpenBlob(
		wrapped.subspan(kNonceBytes),
		wrapped.first(kNonceBytes),
		wrappingKey);
	if (!plaintext || plaintext->bytes().size() != kKeyBytes) {
		return std::nullopt;
	}
	auto result = SecretKey();
	std::copy(
		plaintext->bytes().begin(),
		plaintext->bytes().end(),
		result.bytes().begin());
	return result;
}

} // namespace Leemen::Sync
