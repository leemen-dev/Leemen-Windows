#include "leemen/sync_backend.h"

#include "leemen/sync_blob.h"

#include <openssl/crypto.h>
#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <utility>

namespace Leemen::Sync::Backend {
namespace {

using Object = JsonValue::Object;
using Array = JsonValue::Array;

struct Invalid final : std::exception {};

[[noreturn]] void Fail() {
	throw Invalid();
}

void Cleanse(std::string &value) {
	if (!value.empty()) {
		OPENSSL_cleanse(value.data(), value.size());
	}
}

void Cleanse(JsonValue &value) {
	if (auto text = std::get_if<std::string>(&value.value)) {
		Cleanse(*text);
	} else if (auto array = std::get_if<Array>(&value.value)) {
		for (auto &entry : *array) {
			Cleanse(entry);
		}
	} else if (auto object = std::get_if<Object>(&value.value)) {
		for (auto &[key, entry] : *object) {
			Cleanse(entry);
		}
	}
}

struct SensitiveJson {
	JsonValue value;
	~SensitiveJson() { Cleanse(value); }
};

struct SensitiveString {
	std::string value;
	~SensitiveString() { Cleanse(value); }
};

const Object &AsObject(const JsonValue &value) {
	const auto result = std::get_if<Object>(&value.value);
	if (!result) Fail();
	return *result;
}

const Array &AsArray(const JsonValue &value) {
	const auto result = std::get_if<Array>(&value.value);
	if (!result || result->size() > 1024) Fail();
	return *result;
}

const JsonValue *Find(const Object &object, const char *key) {
	const auto i = object.find(key);
	return (i == object.end()) ? nullptr : &i->second;
}

const JsonValue &Required(const Object &object, const char *key) {
	const auto result = Find(object, key);
	if (!result) Fail();
	return *result;
}

bool IsNull(const JsonValue &value) {
	return std::holds_alternative<std::nullptr_t>(value.value);
}

const std::string &String(
		const JsonValue &value,
		std::size_t limit,
		bool allowEmpty = false) {
	const auto result = std::get_if<std::string>(&value.value);
	if (!result || result->size() > limit || (!allowEmpty && result->empty())) Fail();
	return *result;
}

bool Boolean(const JsonValue &value) {
	const auto result = std::get_if<bool>(&value.value);
	if (!result) Fail();
	return *result;
}

std::int64_t Integer(const JsonValue &value, std::int64_t minimum) {
	const auto result = ExactInt64(value);
	if (!result || *result < minimum || *result > kMaxSafeInteger) Fail();
	return *result;
}

std::int64_t Timestamp(const JsonValue &value) {
	const auto result = ParseTimestamp(String(value, 24));
	if (!result) Fail();
	return *result;
}

std::optional<std::int64_t> NullableTimestamp(const JsonValue &value) {
	return IsNull(value) ? std::nullopt : std::make_optional(Timestamp(value));
}

std::optional<std::string> NullableString(const JsonValue &value, std::size_t limit) {
	return IsNull(value) ? std::nullopt : std::make_optional(String(value, limit, true));
}

std::string Uuid(const JsonValue &value) {
	auto result = CanonicalUuid(String(value, 36));
	if (!result) Fail();
	return std::move(*result);
}

PrivacyMode Mode(const JsonValue &value) {
	const auto &mode = String(value, 16);
	if (mode == "default") return PrivacyMode::Default;
	if (mode == "max") return PrivacyMode::Maximum;
	Fail();
}

SensitiveJson Parse(std::string_view body) {
	auto parsed = ParseJson(body, { kMaxResponseBytes, 24, 32768 });
	if (!parsed.value) Fail();
	return { std::move(*parsed.value) };
}

SecretBytes CopySecret(std::string_view value) {
	auto result = SecretBytes(value.size());
	std::copy(value.begin(), value.end(), result.bytes().begin());
	return result;
}

std::string Base64(std::span<const unsigned char> value) {
	const auto size = sodium_base64_encoded_len(value.size(), sodium_base64_VARIANT_ORIGINAL);
	auto result = std::string(size, '\0');
	sodium_bin2base64(result.data(), result.size(), value.data(), value.size(),
		sodium_base64_VARIANT_ORIGINAL);
	result.resize(size - 1);
	return result;
}

SecretBytes Binary(const JsonValue &value, std::size_t minimum, std::size_t maximum) {
	const auto &text = String(value, 4 * ((maximum + 2) / 3));
	if (text.size() % 4) Fail();
	const auto padding = (text.back() == '=')
		? ((text[text.size() - 2] == '=') ? 2U : 1U) : 0U;
	const auto size = text.size() / 4 * 3 - padding;
	if (size < minimum || size > maximum) Fail();
	auto result = SecretBytes(size);
	auto written = std::size_t(0);
	const char *end = nullptr;
	if (sodium_base642bin(result.bytes().data(), size, text.data(), text.size(),
			nullptr, &written, &end, sodium_base64_VARIANT_ORIGINAL) != 0
		|| written != size || end != text.data() + text.size()) {
		Fail();
	}
	const auto encoded = SensitiveString{ Base64(result.bytes()) };
	if (encoded.value != text) Fail();
	return result;
}

template <std::size_t Size>
std::array<unsigned char, Size> BinaryArray(const JsonValue &value) {
	const auto bytes = Binary(value, Size, Size);
	auto result = std::array<unsigned char, Size>();
	std::ranges::copy(bytes.bytes(), result.begin());
	return result;
}

AccountKey ReadKey(const Object &object) {
	const auto mode = Mode(Required(object, "mode"));
	const auto master = Find(object, "k_master");
	const auto needsWrap = Find(object, "needs_wrap");
	if (mode == PrivacyMode::Default) {
		if (needsWrap && Boolean(*needsWrap)) {
			if (master) Fail();
			return NeedsDefaultWrap();
		}
		if (!master) Fail();
		const auto decoded = Binary(*master, kKeyBytes, kKeyBytes);
		auto key = SecretKey();
		std::ranges::copy(decoded.bytes(), key.bytes().begin());
		return DefaultKey{ std::move(key) };
	}
	if (master || needsWrap) Fail();
	return MaximumPrivacyKey{
		BinaryArray<kWrappedKeyBytes>(Required(object, "wrapped_k_master_pw")),
		BinaryArray<kSaltBytes>(Required(object, "salt_pw")),
		BinaryArray<kWrappedKeyBytes>(Required(object, "wrapped_k_master_recovery")),
		BinaryArray<kSaltBytes>(Required(object, "salt_recovery")),
		Integer(Required(object, "wrap_version"), 1),
	};
}

VersionedBlob ReadBlob(const Object &object) {
	const auto cipher = Binary(Required(object, "encrypted_data"), kTagBytes, kMaxCiphertextBytes);
	auto result = VersionedBlob();
	result.encrypted.nonce = BinaryArray<kNonceBytes>(Required(object, "nonce"));
	result.encrypted.ciphertext.assign(cipher.bytes().begin(), cipher.bytes().end());
	result.version = Integer(Required(object, "version"), 1);
	result.updatedAtMs = Timestamp(Required(object, "updated_at"));
	return result;
}

RemoteBlob ReadBootstrapBlob(const JsonValue &value) {
	const auto &object = AsObject(value);
	const auto &state = String(Required(object, "state"), 16);
	if (state == "present") return ReadBlob(object);
	if (state != "absent" || Integer(Required(object, "version"), 0) != 0
		|| Find(object, "encrypted_data") || Find(object, "nonce")) {
		Fail();
	}
	return AbsentBlob();
}

bool ValidToken(std::string_view value) {
	return value.size() <= 16384 && !value.empty()
		&& std::ranges::all_of(value, [](unsigned char ch) {
			return ch > 32 && ch < 127;
		});
}

AuthReply ReadAuth(const Object &object) {
	const auto &token = String(Required(object, "token"), 16384);
	if (!ValidToken(token)) Fail();
	auto result = AuthReply();
	result.token = CopySecret(token);
	result.generation = {
		Uuid(Required(object, "master_account_id")),
		Uuid(Required(object, "sync_account_id")),
	};
	result.privacyMode = Mode(Required(object, "privacy_mode"));
	result.created = Boolean(Required(object, "created"));
	if (const auto bootstrap = Find(object, "bootstrap")) {
		try {
			const auto &data = AsObject(*bootstrap);
			if (Integer(Required(data, "schema_version"), 1) != 1) Fail();
			auto key = ReadKey(AsObject(Required(data, "key")));
			if (std::holds_alternative<MaximumPrivacyKey>(key)
				!= (result.privacyMode == PrivacyMode::Maximum)) {
				Fail();
			}
			auto filter = ReadBootstrapBlob(Required(data, "filter"));
			auto content = ReadBootstrapBlob(Required(data, "content"));
			result.bootstrap = Bootstrap{
				std::move(key), std::move(filter), std::move(content) };
			result.bootstrapRequiresFallback = false;
		} catch (const Invalid &) {
			result.bootstrap.reset();
		}
	}
	return result;
}

MeReply ReadMe(const Object &object) {
	auto result = MeReply();
	if (const auto now = Find(object, "server_now"); now && !IsNull(*now)) {
		result.serverNowMs = Timestamp(*now);
		if (*result.serverNowMs <= 0) Fail();
	}
	const auto &account = AsObject(Required(object, "account"));
	result.account.generation = {
		Uuid(Required(account, "id")), Uuid(Required(account, "sync_account_id")) };
	result.account.telegramUserId = Integer(Required(account, "telegram_user_id"), 1);
	result.account.privacyMode = Mode(Required(account, "privacy_mode"));
	result.account.needsWrap = Boolean(Required(account, "needs_wrap"));
	if (result.account.needsWrap && result.account.privacyMode != PrivacyMode::Default) Fail();
	if (const auto kz = Find(account, "kz_consent_required")) {
		result.account.kzConsentRequired = Boolean(*kz);
	}
	result.account.email = NullableString(Required(account, "email"), 1024);
	result.account.emailVerifiedAtMs = NullableTimestamp(Required(account, "email_verified_at"));
	result.account.upgradedToMaximumAtMs = NullableTimestamp(Required(account, "upgraded_to_max_at"));
	result.account.createdAtMs = Timestamp(Required(account, "created_at"));
	for (const auto &entry : AsArray(Required(object, "entitlements"))) {
		const auto &fields = AsObject(entry);
		result.entitlements.push_back({
			String(Required(fields, "kind"), 64),
			String(Required(fields, "source"), 64),
			NullableTimestamp(Required(fields, "expires_at")),
			Timestamp(Required(fields, "created_at")),
		});
	}
	for (const auto &entry : AsArray(Required(object, "devices"))) {
		const auto &fields = AsObject(entry);
		result.devices.push_back({
			Uuid(Required(fields, "id")),
			NullableString(Required(fields, "device_name"), 512),
			String(Required(fields, "platform"), 64),
			Timestamp(Required(fields, "created_at")),
			Timestamp(Required(fields, "last_seen_at")),
		});
	}
	const auto &consents = AsObject(Required(object, "consents"));
	if (consents.size() > 128) Fail();
	for (const auto &[type, entry] : consents) {
		if (type.empty() || type.size() > 64) Fail();
		const auto &fields = AsObject(entry);
		result.consents.emplace(type, Consent{
			Boolean(Required(fields, "granted")),
			String(Required(fields, "version"), 128),
		});
	}
	return result;
}

template <typename Value, typename Reader>
Reply<Value> ParseReply(int status, std::string_view body, Reader reader) {
	if (status != 200) return { std::nullopt, ParseFailure(status, body) };
	try {
		const auto parsed = Parse(body);
		return { reader(AsObject(parsed.value)), {} };
	} catch (const Invalid &) {
		return { std::nullopt, { FailureKind::Malformed, status, "invalid_response", {}, {} } };
	}
}

JsonValue Text(std::string value) {
	return JsonValue{ std::move(value) };
}

JsonValue Number(std::int64_t value) {
	return JsonValue{ JsonNumber{ std::to_string(value) } };
}

std::optional<SecretBytes> EncodeRequest(Object object) {
	const auto json = SensitiveJson{ JsonValue{ std::move(object) } };
	auto encoded = EncodeJson(json.value, { kMaxResponseBytes, 24, 32768 });
	if (!encoded) return std::nullopt;
	const auto guarded = SensitiveString{ std::move(*encoded) };
	return CopySecret(guarded.value);
}

} // namespace

std::optional<std::string> CanonicalUuid(std::string_view value) {
	if (value.size() != 36) return std::nullopt;
	auto result = std::string(value);
	auto nonzero = false;
	for (auto i = std::size_t(0); i != result.size(); ++i) {
		auto &ch = result[i];
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (ch != '-') return std::nullopt;
			continue;
		}
		if (ch >= 'A' && ch <= 'F') ch = char(ch + ('a' - 'A'));
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return std::nullopt;
		nonzero = nonzero || ch != '0';
	}
	return nonzero ? std::make_optional(std::move(result)) : std::nullopt;
}

std::optional<std::int64_t> ParseTimestamp(std::string_view value) {
	if (value.size() != 24 || value[4] != '-' || value[7] != '-'
		|| value[10] != 'T' || value[13] != ':' || value[16] != ':'
		|| value[19] != '.' || value[23] != 'Z') return std::nullopt;
	const auto digits = [&](std::size_t offset, std::size_t count) {
		auto result = 0;
		for (auto i = offset; i < offset + count; ++i) {
			if (value[i] < '0' || value[i] > '9') return -1;
			result = result * 10 + value[i] - '0';
		}
		return result;
	};
	const auto year = digits(0, 4);
	const auto month = digits(5, 2);
	const auto day = digits(8, 2);
	const auto hour = digits(11, 2);
	const auto minute = digits(14, 2);
	const auto second = digits(17, 2);
	const auto millis = digits(20, 3);
	if (year < 0 || month < 1 || day < 1 || hour < 0 || hour > 23
		|| minute < 0 || minute > 59 || second < 0 || second > 59 || millis < 0) {
		return std::nullopt;
	}
	const auto date = std::chrono::year_month_day(
		std::chrono::year(year), std::chrono::month(unsigned(month)),
		std::chrono::day(unsigned(day)));
	if (!date.ok()) return std::nullopt;
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::sys_days(date).time_since_epoch()).count()
		+ ((std::int64_t(hour) * 60 + minute) * 60 + second) * 1000 + millis;
}

Failure ParseFailure(int httpStatus, std::string_view body) {
	auto result = Failure{ FailureKind::Rejected, httpStatus, {}, {}, {} };
	try {
		const auto parsed = Parse(body);
		const auto &object = AsObject(parsed.value);
		const auto &error = AsObject(Required(object, "error"));
		const auto &code = String(Required(error, "code"), 128);
		if (std::ranges::all_of(code, [](char ch) {
			return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_';
		})) result.code = code;
		if (const auto version = Find(object, "current_version")) {
			result.currentVersion = Integer(*version, 0);
		}
		if (const auto version = Find(object, "current_wrap_version")) {
			result.currentWrapVersion = Integer(*version, 1);
		}
	} catch (const Invalid &) {
		result.currentVersion.reset();
		result.currentWrapVersion.reset();
	}
	if (httpStatus == 0 || httpStatus == 408 || (httpStatus >= 500 && httpStatus <= 599)) {
		result.kind = FailureKind::Retryable;
	} else if (httpStatus == 429) {
		result.kind = FailureKind::RateLimited;
	} else if (httpStatus == 401) {
		result.kind = (result.code == "auth_account_deleted") ? FailureKind::AccountDeleted
			: (result.code == "init_data_replayed") ? FailureKind::InitDataReplayed
			: FailureKind::Unauthorized;
	} else if (httpStatus == 400 && result.code.starts_with("init_data_")) {
		result.kind = FailureKind::InitDataInvalid;
	} else if (httpStatus == 409 && result.code == "account_generation_changed") {
		result.kind = FailureKind::GenerationChanged;
	} else if (httpStatus == 409 && result.code == "version_conflict") {
		result.kind = FailureKind::VersionConflict;
	}
	return result;
}

Reply<AuthReply> ParseAuth(int status, std::string_view body) {
	return ParseReply<AuthReply>(status, body, ReadAuth);
}

Reply<AccountKey> ParseAccountKey(int status, std::string_view body) {
	return ParseReply<AccountKey>(status, body, ReadKey);
}

Reply<RemoteBlob> ParseBlob(int status, std::string_view body) {
	if (status == 404) {
		auto failure = ParseFailure(status, body);
		if (failure.code == "blob_not_found") return { RemoteBlob{ AbsentBlob() }, {} };
		return { std::nullopt, std::move(failure) };
	}
	return ParseReply<RemoteBlob>(status, body, [](const Object &object) -> RemoteBlob {
		return ReadBlob(object);
	});
}

Reply<PutReceipt> ParsePut(int status, std::string_view body) {
	return ParseReply<PutReceipt>(status, body, [](const Object &object) {
		return PutReceipt{ Integer(Required(object, "version"), 1),
			Timestamp(Required(object, "updated_at")) };
	});
}

Reply<DeviceReceipt> ParseDevice(int status, std::string_view body) {
	return ParseReply<DeviceReceipt>(status, body, [](const Object &object) {
		return DeviceReceipt{ Uuid(Required(object, "device_id")),
			Boolean(Required(object, "created")) };
	});
}

Reply<WrapReceipt> ParseWrapReceipt(int status, std::string_view body) {
	return ParseReply<WrapReceipt>(status, body, [](const Object &object) {
		if (!Boolean(Required(object, "ok"))) Fail();
		return WrapReceipt{ Integer(Required(object, "wrap_version"), 1) };
	});
}

Reply<MeReply> ParseMe(int status, std::string_view body) {
	return ParseReply<MeReply>(status, body, ReadMe);
}

Reply<std::string> ParseSessionStatus(int status, std::string_view body) {
	return ParseReply<std::string>(status, body, [](const Object &object) {
		if (!Boolean(Required(object, "active"))) Fail();
		return Uuid(Required(object, "master_account_id"));
	});
}

Reply<bool> ParseOk(int status, std::string_view body) {
	return ParseReply<bool>(status, body, [](const Object &object) {
		if (!Boolean(Required(object, "ok"))) Fail();
		return true;
	});
}

std::optional<PremiumStatus> PremiumAtServerTime(const MeReply &reply) {
	if (!reply.serverNowMs || *reply.serverNowMs <= 0) return std::nullopt;
	auto result = PremiumStatus();
	for (const auto &entitlement : reply.entitlements) {
		if (entitlement.kind != "premium") continue;
		if (!entitlement.expiresAtMs) return PremiumStatus{ PremiumAccess::Perpetual, 0 };
		if (*entitlement.expiresAtMs > *reply.serverNowMs) {
			result.access = PremiumAccess::Expiring;
			result.expiresAtMs = std::max(result.expiresAtMs, *entitlement.expiresAtMs);
		}
	}
	return result;
}

std::optional<SecretBytes> EncodeAuthRequest(
		std::string_view initData,
		std::optional<Generation> renewal) {
	if (initData.empty() || initData.size() > 65536) return std::nullopt;
	auto object = Object();
	object.emplace("initData", Text(std::string(initData)));
	if (renewal) {
		const auto master = CanonicalUuid(renewal->masterAccountId);
		const auto sync = CanonicalUuid(renewal->syncAccountId);
		if (!master || !sync) {
			auto cleanup = SensitiveJson{ JsonValue{ std::move(object) } };
			return std::nullopt;
		}
		object.emplace("mode", Text("renew"));
		object.emplace("expected_master_account_id", Text(*master));
		object.emplace("expected_sync_account_id", Text(*sync));
	} else {
		object.emplace("bootstrap_version", Number(1));
	}
	return EncodeRequest(std::move(object));
}

std::optional<SecretBytes> EncodePutRequest(
		const EncryptedBlob &encrypted,
		std::int64_t previousVersion) {
	if (previousVersion < 0 || previousVersion >= kMaxSafeInteger
		|| encrypted.ciphertext.size() < kTagBytes
		|| encrypted.ciphertext.size() > kMaxCiphertextBytes) return std::nullopt;
	return EncodeRequest({
		{ "encrypted_data", Text(Base64(encrypted.ciphertext)) },
		{ "nonce", Text(Base64(encrypted.nonce)) },
		{ "prev_version", Number(previousVersion) },
	});
}

std::optional<SecretBytes> EncodeDefaultWrapRequest(std::span<const unsigned char> masterKey) {
	if (masterKey.size() != kKeyBytes) return std::nullopt;
	auto object = Object();
	object.emplace("k_master", Text(Base64(masterKey)));
	return EncodeRequest(std::move(object));
}

std::optional<SecretBytes> EncodeUpgradePrivacyRequest(
		std::span<const unsigned char> wrappedPassword,
		std::span<const unsigned char> passwordSalt,
		std::span<const unsigned char> wrappedRecovery,
		std::span<const unsigned char> recoverySalt) {
	if (wrappedPassword.size() != kWrappedKeyBytes
		|| passwordSalt.size() != kSaltBytes
		|| wrappedRecovery.size() != kWrappedKeyBytes
		|| recoverySalt.size() != kSaltBytes) return std::nullopt;
	return EncodeRequest({
		{ "wrapped_k_master_pw", Text(Base64(wrappedPassword)) },
		{ "salt_pw", Text(Base64(passwordSalt)) },
		{ "wrapped_k_master_recovery", Text(Base64(wrappedRecovery)) },
		{ "salt_recovery", Text(Base64(recoverySalt)) },
	});
}

std::optional<SecretBytes> EncodePasswordWrapRequest(
		std::span<const unsigned char> wrappedPassword,
		std::span<const unsigned char> passwordSalt,
		std::int64_t previousWrapVersion) {
	if (wrappedPassword.size() != kWrappedKeyBytes
		|| passwordSalt.size() != kSaltBytes
		|| previousWrapVersion < 1
		|| previousWrapVersion >= kMaxSafeInteger) return std::nullopt;
	return EncodeRequest({
		{ "wrapped_k_master_pw", Text(Base64(wrappedPassword)) },
		{ "salt_pw", Text(Base64(passwordSalt)) },
		{ "prev_wrap_version", Number(previousWrapVersion) },
	});
}

std::optional<SecretBytes> EncodeDeviceRequest(
		std::span<const unsigned char> publicKey,
		std::optional<std::string_view> deviceName) {
	if (publicKey.size() != kKeyBytes) return std::nullopt;
	if (deviceName) {
		if (deviceName->size() > 512) return std::nullopt;
		auto units = std::size_t(0);
		for (const auto byte : *deviceName) {
			const auto ch = static_cast<unsigned char>(byte);
			if ((ch & 0xc0) != 0x80) units += (ch >= 0xf0) ? 2 : 1;
		}
		if (units > 128) return std::nullopt;
	}
	auto object = Object();
	object.emplace("public_key", Text(Base64(publicKey)));
	object.emplace("platform", Text("windows"));
	if (deviceName) object.emplace("device_name", Text(std::string(*deviceName)));
	return EncodeRequest(std::move(object));
}

} // namespace Leemen::Sync::Backend
