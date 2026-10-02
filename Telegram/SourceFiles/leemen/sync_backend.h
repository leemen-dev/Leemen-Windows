#pragma once

#include "leemen/sync_crypto.h"

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace Leemen::Sync::Backend {

inline constexpr auto kMaxSafeInteger = std::int64_t(9'007'199'254'740'991);
inline constexpr auto kMaxResponseBytes = std::size_t(768 * 1024);
inline constexpr auto kWindowsDeviceRegistrationSupported = false;

enum class FailureKind {
	Malformed,
	Retryable,
	RateLimited,
	Unauthorized,
	InitDataInvalid,
	InitDataReplayed,
	AccountDeleted,
	GenerationChanged,
	VersionConflict,
	Rejected,
};

struct Failure {
	FailureKind kind = FailureKind::Malformed;
	int httpStatus = 0;
	std::string code;
	std::optional<std::int64_t> currentVersion;
	std::optional<std::int64_t> currentWrapVersion;
};

template <typename Value>
struct Reply {
	std::optional<Value> value;
	Failure failure;
};

enum class PrivacyMode { Default, Maximum };

struct Generation {
	std::string masterAccountId;
	std::string syncAccountId;
	bool operator==(const Generation&) const = default;
};

struct DefaultKey { SecretKey masterKey; };
struct NeedsDefaultWrap {};
struct MaximumPrivacyKey {
	WrappedKey wrappedPassword = {};
	Salt passwordSalt = {};
	WrappedKey wrappedRecovery = {};
	Salt recoverySalt = {};
	std::int64_t wrapVersion = 0;
};
using AccountKey = std::variant<DefaultKey, NeedsDefaultWrap, MaximumPrivacyKey>;

struct AbsentBlob {};
struct VersionedBlob {
	EncryptedBlob encrypted;
	std::int64_t version = 0;
	std::int64_t updatedAtMs = 0;
};
using RemoteBlob = std::variant<AbsentBlob, VersionedBlob>;

struct Bootstrap {
	AccountKey key;
	RemoteBlob filter;
	RemoteBlob content;
};

struct AuthReply {
	SecretBytes token;
	Generation generation;
	PrivacyMode privacyMode = PrivacyMode::Default;
	bool created = false;
	std::optional<Bootstrap> bootstrap;
	bool bootstrapRequiresFallback = true;
};

struct PutReceipt {
	std::int64_t version = 0;
	std::int64_t updatedAtMs = 0;
};

struct DeviceReceipt {
	std::string deviceId;
	bool created = false;
};

struct WrapReceipt {
	std::int64_t wrapVersion = 0;
};

struct PromoReceipt {
	std::string entitlementId;
	std::string kind;
	std::optional<std::int64_t> expiresAtMs;
};

struct AccountMetadata {
	Generation generation;
	std::int64_t telegramUserId = 0;
	PrivacyMode privacyMode = PrivacyMode::Default;
	bool needsWrap = false;
	bool kzConsentRequired = false;
	std::optional<std::string> email;
	std::optional<std::int64_t> emailVerifiedAtMs;
	std::optional<std::int64_t> upgradedToMaximumAtMs;
	std::int64_t createdAtMs = 0;
};

struct Entitlement {
	std::string kind;
	std::string source;
	std::optional<std::int64_t> expiresAtMs;
	std::int64_t createdAtMs = 0;
};

struct Device {
	std::string id;
	std::optional<std::string> name;
	std::string platform;
	std::int64_t createdAtMs = 0;
	std::int64_t lastSeenAtMs = 0;
};

struct Consent {
	bool granted = false;
	std::string version;
};

inline constexpr auto kCurrentTermsVersion = std::string_view("2026-08-21");
enum class ConsentType { Terms, KzCrossBorder };

struct MeReply {
	std::optional<std::int64_t> serverNowMs;
	AccountMetadata account;
	std::vector<Entitlement> entitlements;
	std::vector<Device> devices;
	std::map<std::string, Consent> consents;
};

enum class PremiumAccess { Inactive, Expiring, Perpetual };
struct PremiumStatus {
	PremiumAccess access = PremiumAccess::Inactive;
	std::int64_t expiresAtMs = 0;
};

[[nodiscard]] std::optional<std::string> CanonicalUuid(std::string_view value);
[[nodiscard]] std::optional<std::int64_t> ParseTimestamp(std::string_view value);
[[nodiscard]] Failure ParseFailure(int httpStatus, std::string_view body);
[[nodiscard]] Reply<AuthReply> ParseAuth(int httpStatus, std::string_view body);
[[nodiscard]] Reply<AccountKey> ParseAccountKey(int httpStatus, std::string_view body);
[[nodiscard]] Reply<RemoteBlob> ParseBlob(int httpStatus, std::string_view body);
[[nodiscard]] Reply<PutReceipt> ParsePut(int httpStatus, std::string_view body);
[[nodiscard]] Reply<DeviceReceipt> ParseDevice(int httpStatus, std::string_view body);
[[nodiscard]] Reply<WrapReceipt> ParseWrapReceipt(int httpStatus, std::string_view body);
[[nodiscard]] Reply<PromoReceipt> ParsePromo(int httpStatus, std::string_view body);
[[nodiscard]] Reply<MeReply> ParseMe(int httpStatus, std::string_view body);
[[nodiscard]] Reply<std::string> ParseSessionStatus(int httpStatus, std::string_view body);
[[nodiscard]] Reply<bool> ParseOk(int httpStatus, std::string_view body);
[[nodiscard]] std::optional<PremiumStatus> PremiumAtServerTime(const MeReply &reply);
[[nodiscard]] bool HasCurrentConsent(const MeReply &reply, ConsentType type);
[[nodiscard]] bool HasRequiredConsents(const MeReply &reply);
[[nodiscard]] std::optional<SecretBytes> EncodeConsentRequest(
	ConsentType type,
	std::string_view locale);
[[nodiscard]] std::optional<SecretBytes> EncodePromoRequest(std::string_view code);

[[nodiscard]] std::optional<SecretBytes> EncodeAuthRequest(
	std::string_view initData,
	std::optional<Generation> renewal = std::nullopt);
[[nodiscard]] std::optional<SecretBytes> EncodePutRequest(
	const EncryptedBlob &encrypted,
	std::int64_t previousVersion);
[[nodiscard]] std::optional<SecretBytes> EncodeDefaultWrapRequest(
	std::span<const unsigned char> masterKey);
[[nodiscard]] std::optional<SecretBytes> EncodeUpgradePrivacyRequest(
	std::span<const unsigned char> wrappedPassword,
	std::span<const unsigned char> passwordSalt,
	std::span<const unsigned char> wrappedRecovery,
	std::span<const unsigned char> recoverySalt);
[[nodiscard]] std::optional<SecretBytes> EncodePasswordWrapRequest(
	std::span<const unsigned char> wrappedPassword,
	std::span<const unsigned char> passwordSalt,
	std::int64_t previousWrapVersion);
[[nodiscard]] std::optional<SecretBytes> EncodeDeviceRequest(
	std::span<const unsigned char> publicKey,
	std::optional<std::string_view> deviceName = std::nullopt);

} // namespace Leemen::Sync::Backend
