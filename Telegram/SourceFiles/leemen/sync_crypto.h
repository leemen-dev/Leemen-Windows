#pragma once

#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace Leemen::Sync {

inline constexpr auto kKeyBytes = std::size_t(32);
inline constexpr auto kNonceBytes = std::size_t(24);
inline constexpr auto kTagBytes = std::size_t(16);
inline constexpr auto kSaltBytes = std::size_t(16);
inline constexpr auto kWrappedKeyBytes = kNonceBytes + kKeyBytes + kTagBytes;
inline constexpr auto kMaxCiphertextBytes = std::size_t(256 * 1024);
inline constexpr auto kMaxSecretBytes = std::size_t(4096);

using Nonce = std::array<unsigned char, kNonceBytes>;
using Salt = std::array<unsigned char, kSaltBytes>;
using WrappedKey = std::array<unsigned char, kWrappedKeyBytes>;

class SecretKey final {
public:
	SecretKey() = default;
	SecretKey(const SecretKey&) = delete;
	SecretKey &operator=(const SecretKey&) = delete;
	SecretKey(SecretKey &&other) noexcept;
	SecretKey &operator=(SecretKey &&other) noexcept;
	~SecretKey();

	[[nodiscard]] std::span<unsigned char, kKeyBytes> bytes();
	[[nodiscard]] std::span<const unsigned char, kKeyBytes> bytes() const;
	void clear() noexcept;

private:
	std::array<unsigned char, kKeyBytes> _bytes = {};
};

class SecretBytes final {
public:
	explicit SecretBytes(std::size_t size = 0);
	SecretBytes(const SecretBytes&) = delete;
	SecretBytes &operator=(const SecretBytes&) = delete;
	SecretBytes(SecretBytes &&other) noexcept;
	SecretBytes &operator=(SecretBytes &&other) noexcept;
	~SecretBytes();

	[[nodiscard]] std::span<unsigned char> bytes();
	[[nodiscard]] std::span<const unsigned char> bytes() const;
	void clear() noexcept;

private:
	std::vector<unsigned char> _bytes;
};

struct EncryptedBlob {
	Nonce nonce = {};
	std::vector<unsigned char> ciphertext;
};

[[nodiscard]] std::optional<SecretKey> RandomKey();
[[nodiscard]] std::optional<Salt> RandomSalt();
[[nodiscard]] std::optional<EncryptedBlob> SealBlob(
	std::span<const unsigned char> plaintext,
	std::span<const unsigned char> key);
[[nodiscard]] std::optional<SecretBytes> OpenBlob(
	std::span<const unsigned char> ciphertext,
	std::span<const unsigned char> nonce,
	std::span<const unsigned char> key);

// Inputs are raw UTF-8 bytes; callers own normalization and input-buffer wiping.
// Run KDF operations off the UI thread; their fixed 64 MiB cost matches Android.
[[nodiscard]] std::optional<SecretKey> DerivePinHash(
	std::string_view pin,
	std::span<const unsigned char> salt);
[[nodiscard]] bool VerifySyncedPin(
	std::string_view pin,
	std::span<const unsigned char> salt,
	std::span<const unsigned char> digest);
[[nodiscard]] std::optional<SecretKey> DeriveWrappingKey(
	std::string_view secret,
	std::span<const unsigned char> salt);
[[nodiscard]] std::optional<WrappedKey> WrapMasterKey(
	std::span<const unsigned char> masterKey,
	std::span<const unsigned char> wrappingKey);
[[nodiscard]] std::optional<SecretKey> UnwrapMasterKey(
	std::span<const unsigned char> wrapped,
	std::span<const unsigned char> wrappingKey);

} // namespace Leemen::Sync
