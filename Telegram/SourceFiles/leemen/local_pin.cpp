#include "leemen/local_pin.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>

namespace Leemen {
namespace {

constexpr auto kIterations = 600'000;

struct TemporaryDigest {
	std::array<unsigned char, 32> bytes = {};
	~TemporaryDigest();
};

TemporaryDigest::~TemporaryDigest() {
	OPENSSL_cleanse(bytes.data(), bytes.size());
}

bool ValidPin(std::string_view pin) {
	return pin.size() >= 4
		&& pin.size() <= 12
		&& std::all_of(pin.begin(), pin.end(), [](char value) {
			return value >= '0' && value <= '9';
		});
}

bool DerivePin(
		std::string_view pin,
		const std::array<unsigned char, 16> &salt,
		std::array<unsigned char, 32> &digest) {
	return PKCS5_PBKDF2_HMAC(
		pin.data(),
		static_cast<int>(pin.size()),
		salt.data(),
		static_cast<int>(salt.size()),
		kIterations,
		EVP_sha256(),
		static_cast<int>(digest.size()),
		digest.data()) == 1;
}

} // namespace

std::optional<LocalPin> CreateLocalPin(std::string_view pin) {
	if (!ValidPin(pin)) {
		return std::nullopt;
	}
	auto result = LocalPin();
	if (RAND_bytes(
			result.salt.data(),
			static_cast<int>(result.salt.size())) != 1) {
		return std::nullopt;
	}
	auto derived = TemporaryDigest();
	if (!DerivePin(pin, result.salt, derived.bytes)) {
		return std::nullopt;
	}
	result.digest = derived.bytes;
	return result;
}

bool VerifyLocalPin(std::string_view pin, const LocalPin &stored) {
	if (!ValidPin(pin)) {
		return false;
	}
	auto derived = TemporaryDigest();
	return DerivePin(pin, stored.salt, derived.bytes)
		&& CRYPTO_memcmp(
			derived.bytes.data(),
			stored.digest.data(),
			stored.digest.size()) == 0;
}

} // namespace Leemen
