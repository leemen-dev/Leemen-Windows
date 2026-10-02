#include "leemen/sync_backend.h"
#include "leemen/sync_blob.h"

#include <sodium.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <type_traits>

namespace {

using namespace Leemen::Sync;
using namespace Leemen::Sync::Backend;
using Object = JsonValue::Object;
using Array = JsonValue::Array;

constexpr auto kMasterId = "01234567-89ab-4cde-8fab-0123456789ab";
constexpr auto kSyncId = "abcdef01-2345-4678-89ab-cdef01234567";
constexpr auto kNow = "2026-10-03T12:00:00.000Z";
constexpr auto kFuture = "2026-10-04T12:00:00.000Z";
auto Checks = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

JsonValue Text(std::string value) { return { std::move(value) }; }
JsonValue Number(std::string token) { return { JsonNumber{ std::move(token) } }; }
JsonValue Boolean(bool value) { return { value }; }

Object &Fields(JsonValue &value) { return std::get<Object>(value.value); }
const Object &Fields(const JsonValue &value) { return std::get<Object>(value.value); }

std::string Body(const JsonValue &value) {
	const auto result = EncodeJson(value, { kMaxResponseBytes, 24, 32768 });
	Check(result.has_value(), "serialize public test fixture");
	return *result;
}

std::string_view View(const SecretBytes &value) {
	return { reinterpret_cast<const char*>(value.bytes().data()), value.bytes().size() };
}

JsonValue Request(const std::optional<SecretBytes> &value) {
	Check(value.has_value(), "request encoding succeeded");
	auto parsed = ParseJson(View(*value), { kMaxResponseBytes, 24, 32768 });
	Check(parsed.value.has_value(), "encoded request is valid JSON");
	return std::move(*parsed.value);
}

std::string Base64(std::size_t size) {
	const auto bytes = std::vector<unsigned char>(size);
	auto text = std::string(sodium_base64_encoded_len(size, sodium_base64_VARIANT_ORIGINAL), '\0');
	sodium_bin2base64(text.data(), text.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
	text.pop_back();
	return text;
}

JsonValue Key(bool maximum = false) {
	if (!maximum) return { Object{ { "mode", Text("default") }, { "k_master", Text(Base64(32)) } } };
	return { Object{
		{ "mode", Text("max") },
		{ "wrapped_k_master_pw", Text(Base64(72)) }, { "salt_pw", Text(Base64(16)) },
		{ "wrapped_k_master_recovery", Text(Base64(72)) }, { "salt_recovery", Text(Base64(16)) },
		{ "wrap_version", Number("1") },
	} };
}

JsonValue Blob() {
	return { Object{
		{ "encrypted_data", Text(Base64(16)) }, { "nonce", Text(Base64(24)) },
		{ "version", Number("7") }, { "updated_at", Text(kNow) },
	} };
}

JsonValue Auth() {
	return { Object{
		{ "token", Text("public-fixture.token.signature") },
		{ "master_account_id", Text(kMasterId) }, { "sync_account_id", Text(kSyncId) },
		{ "privacy_mode", Text("default") }, { "created", Boolean(false) },
	} };
}

JsonValue BootstrapValue() {
	auto filter = Blob();
	Fields(filter).emplace("state", Text("present"));
	return { Object{
		{ "schema_version", Number("1") }, { "key", Key() },
		{ "filter", std::move(filter) },
		{ "content", JsonValue{ Object{ { "state", Text("absent") }, { "version", Number("0") } } } },
	} };
}

JsonValue EntitlementValue(std::string kind, std::string source, JsonValue expiry) {
	return { Object{
		{ "kind", Text(std::move(kind)) }, { "source", Text(std::move(source)) },
		{ "expires_at", std::move(expiry) }, { "created_at", Text(kNow) },
	} };
}

JsonValue Me() {
	return { Object{
		{ "server_now", Text(kNow) },
		{ "account", JsonValue{ Object{
			{ "id", Text(kMasterId) }, { "sync_account_id", Text(kSyncId) },
			{ "telegram_user_id", Number("123456789") },
			{ "privacy_mode", Text("default") }, { "needs_wrap", Boolean(false) },
			{ "email", {} }, { "email_verified_at", {} }, { "upgraded_to_max_at", {} },
			{ "created_at", Text(kNow) }, { "kz_consent_required", Boolean(true) },
		} } },
		{ "entitlements", JsonValue{ Array{ EntitlementValue("premium", "manual", Text(kFuture)) } } },
		{ "devices", JsonValue{ Array{ JsonValue{ Object{
			{ "id", Text(kSyncId) }, { "device_name", {} }, { "platform", Text("android") },
			{ "created_at", Text(kNow) }, { "last_seen_at", Text(kNow) },
		} } } } },
		{ "consents", JsonValue{ Object{ { "privacy", JsonValue{ Object{
			{ "granted", Boolean(true) }, { "version", Text("2026-09") },
		} } } } } },
	} };
}

void TestIdentifiersAndTime() {
	Check(CanonicalUuid("01234567-89AB-4CDE-8FAB-0123456789AB") == kMasterId, "UUID normalization");
	for (const auto value : { "", "{01234567-89ab-4cde-8fab-0123456789ab}",
		"00000000-0000-0000-0000-000000000000", "01234567-89ab-4cde-8fab-0123456789ag",
		"0123456789ab4cde8fab0123456789ab" }) {
		Check(!CanonicalUuid(value), "reject malformed generation UUID");
	}
	Check(ParseTimestamp("1970-01-01T00:00:00.000Z") == 0, "Unix epoch");
	Check(ParseTimestamp("2000-02-29T00:00:00.001Z") == 951782400001LL, "leap-year timestamp");
	Check(ParseTimestamp("1969-12-31T23:59:59.999Z") == -1, "past expiry remains representable");
	for (const auto value : { "2026-02-29T12:00:00.000Z", "1900-02-29T00:00:00.000Z",
		"2026-13-01T00:00:00.000Z", "2026-01-32T00:00:00.000Z", "2026-10-03T24:00:00.000Z",
		"2026-10-03T12:60:00.000Z", "2026-10-03T12:00:60.000Z", "2026-10-03T12:00:00Z",
		"2026-10-03T12:00:00.000+00:00", " 2026-10-03T12:00:00.000Z", "2026-10-03T12:00:00.00aZ" }) {
		Check(!ParseTimestamp(value), "reject noncanonical timestamp");
	}
}

void TestFailures() {
	const auto deleted = R"({"error":{"code":"auth_account_deleted"}})";
	for (const auto status : { 0, 200, 400, 401, 403, 404, 409, 429, 500, 503 }) {
		Check((ParseFailure(status, deleted).kind == FailureKind::AccountDeleted) == (status == 401),
			"only exact 401 deletion signal is destructive");
	}
	Check(ParseFailure(401, R"({"error":{"code":"init_data_replayed"}})").kind == FailureKind::InitDataReplayed,
		"replay requires fresh initData");
	Check(ParseFailure(400, R"({"error":{"code":"init_data_expired"}})").kind == FailureKind::InitDataInvalid,
		"expired initData separate from session deletion");
	Check(ParseFailure(401, R"({"error":{"code":"auth_invalid"}})").kind == FailureKind::Unauthorized,
		"invalid session separate from deletion");
	Check(ParseFailure(503, "<html>unavailable</html>").kind == FailureKind::Retryable, "gateway 5xx retryable");
	Check(ParseFailure(429, "").kind == FailureKind::RateLimited, "rate limit without JSON");
	Check(ParseFailure(0, "").kind == FailureKind::Retryable, "transport failure retryable");
	Check(ParseFailure(409, R"({"error":{"code":"account_generation_changed"}})").kind == FailureKind::GenerationChanged,
		"generation race not deletion");
	const auto conflict = ParseFailure(409, R"({"error":{"code":"version_conflict"},"current_version":0})");
	Check(conflict.kind == FailureKind::VersionConflict && conflict.currentVersion == 0, "CAS conflict missing-row hint");
	Check(!ParseFailure(409, R"({"error":{"code":"version_conflict"},"current_version":9007199254740992})").currentVersion,
		"unsafe CAS hint discarded");
	for (const auto body : { "", "{", R"({"error":"auth_account_deleted"})",
		R"({"error":{"code":"AUTH_ACCOUNT_DELETED"}})", R"({"error":{"code":"auth_account_deleted\n"}})",
		R"({"error":{"code":"auth_account_deleted","code":"auth_invalid"}})" }) {
		Check(ParseFailure(401, body).kind != FailureKind::AccountDeleted, "malformed error cannot delete session");
	}
}

void TestKeyAndBase64() {
	auto ready = ParseAccountKey(200, Body(Key()));
	Check(ready.value && std::holds_alternative<DefaultKey>(*ready.value), "default key decoded");
	const auto &bytes = std::get<DefaultKey>(*ready.value).masterKey.bytes();
	Check(bytes.size() == 32 && std::ranges::all_of(bytes, [](auto byte) { return byte == 0; }), "exact decoded key");
	const auto needs = ParseAccountKey(200, R"({"mode":"default","needs_wrap":true})");
	Check(needs.value && std::holds_alternative<NeedsDefaultWrap>(*needs.value), "legacy default needs-wrap state");
	const auto maximum = ParseAccountKey(200, Body(Key(true)));
	Check(maximum.value && std::holds_alternative<MaximumPrivacyKey>(*maximum.value), "maximum privacy key envelope");
	auto noncanonical = Base64(32);
	noncanonical[42] = 'B';
	for (const auto &bad : { std::string(), Base64(31), Base64(33), Base64(32).substr(0, 43),
		noncanonical, std::string(43, '_') + "=", std::string(42, 'A') + " =", " " + Base64(32) }) {
		auto key = Key();
		Fields(key)["k_master"] = Text(bad);
		Check(!ParseAccountKey(200, Body(key)).value, "reject malformed or noncanonical base64 key");
	}
	auto ambiguous = Key();
	Fields(ambiguous)["needs_wrap"] = Boolean(true);
	Check(!ParseAccountKey(200, Body(ambiguous)).value, "reject conflicting key states");
	for (const auto name : { "wrapped_k_master_pw", "wrapped_k_master_recovery", "salt_pw", "salt_recovery" }) {
		auto key = Key(true);
		Fields(key)[name] = Text(Base64(15));
		Check(!ParseAccountKey(200, Body(key)).value, "max fields require exact binary sizes");
	}
	for (const auto number : { "0", "-1", "1.1", "9007199254740992" }) {
		auto key = Key(true);
		Fields(key)["wrap_version"] = Number(number);
		Check(!ParseAccountKey(200, Body(key)).value, "max wrap version positive safe integer");
	}
	Check(!ParseAccountKey(200, R"({"mode":"future"})").value, "unknown privacy mode fails closed");
}

void TestAuthAndBootstrap() {
	static_assert(!std::is_copy_constructible_v<AuthReply>);
	static_assert(!std::is_copy_constructible_v<AccountKey>);
	auto auth = Auth();
	auto fallback = ParseAuth(200, Body(auth));
	Check(fallback.value && fallback.value->bootstrapRequiresFallback && !fallback.value->bootstrap,
		"missing bootstrap requires endpoint fallback");
	Check(View(fallback.value->token) == "public-fixture.token.signature", "token bytes retained exactly");
	Fields(auth)["bootstrap"] = BootstrapValue();
	auto full = ParseAuth(200, Body(auth));
	Check(full.value && full.value->bootstrap && !full.value->bootstrapRequiresFallback, "complete bootstrap accepted");
	Check(std::holds_alternative<VersionedBlob>(full.value->bootstrap->filter)
		&& std::holds_alternative<AbsentBlob>(full.value->bootstrap->content), "explicit bootstrap present and absent");
	for (const auto member : { "key", "filter", "content", "schema_version" }) {
		auto damaged = auth;
		Fields(Fields(damaged)["bootstrap"])[member] = {};
		const auto parsed = ParseAuth(200, Body(damaged));
		Check(parsed.value && parsed.value->bootstrapRequiresFallback && !parsed.value->bootstrap,
			"bad bootstrap falls back without converting corruption to absence");
	}
	auto newer = auth;
	Fields(Fields(newer)["bootstrap"])["schema_version"] = Number("2");
	Check(ParseAuth(200, Body(newer)).value->bootstrapRequiresFallback, "unknown bootstrap schema falls back");
	auto mixed = auth;
	Fields(Fields(mixed)["bootstrap"])["key"] = Key(true);
	Check(ParseAuth(200, Body(mixed)).value->bootstrapRequiresFallback, "mixed bootstrap privacy modes rejected");
	for (const auto member : { "token", "master_account_id", "sync_account_id", "privacy_mode", "created" }) {
		auto malformed = auth;
		Fields(malformed)[member] = {};
		Check(!ParseAuth(200, Body(malformed)).value, "malformed auth core cannot become authenticated");
	}
	Fields(auth)["token"] = Text("value\r\nInjected: header");
	Check(!ParseAuth(200, Body(auth)).value, "reject token header injection");
}

void TestBlobAndReceipts() {
	const auto absent = ParseBlob(404, R"({"error":{"code":"blob_not_found"}})");
	Check(absent.value && std::holds_alternative<AbsentBlob>(*absent.value), "only confirmed blob absence");
	for (const auto status : { 0, 200, 400, 401, 403, 500 }) {
		Check(!ParseBlob(status, R"({"error":{"code":"blob_not_found"}})").value, "wrong status is not absence");
	}
	Check(!ParseBlob(404, R"({"error":{"code":"account_not_found"}})").value, "account 404 not blob absence");
	Check(!ParseBlob(404, "").value, "empty 404 not blob absence");
	const auto blob = ParseBlob(200, Body(Blob()));
	Check(blob.value && std::get<VersionedBlob>(*blob.value).version == 7, "blob wire envelope");
	for (const auto size : { 0U, 8U, 23U, 25U, 32U }) {
		auto invalid = Blob();
		Fields(invalid)["nonce"] = Text(Base64(size));
		Check(!ParseBlob(200, Body(invalid)).value, "wire nonce must be 24 bytes");
	}
	for (const auto size : { std::size_t(0), std::size_t(15), kMaxCiphertextBytes + 1 }) {
		auto invalid = Blob();
		Fields(invalid)["encrypted_data"] = Text(Base64(size));
		Check(!ParseBlob(200, Body(invalid)).value, "ciphertext size limits");
	}
	for (const auto version : { "0", "-1", "1.25", "9007199254740992" }) {
		auto invalid = Blob();
		Fields(invalid)["version"] = Number(version);
		Check(!ParseBlob(200, Body(invalid)).value, "wire CAS version positive safe integer");
	}
	auto exact = Blob();
	Fields(exact)["version"] = Number("9007199254740991");
	Check(std::get<VersionedBlob>(*ParseBlob(200, Body(exact)).value).version == kMaxSafeInteger,
		"maximum safe version retained without double rounding");
	Check(ParsePut(200, Body(Blob())).value->version == 7, "PUT acknowledgement parsed");
	const auto device = ParseDevice(200, std::string("{\"device_id\":\"") + kSyncId + "\",\"created\":true}");
	Check(device.value && device.value->created && device.value->deviceId == kSyncId, "device receipt");
	Check(ParseSessionStatus(200, std::string("{\"active\":true,\"master_account_id\":\"") + kMasterId + "\"}").value == kMasterId,
		"active generation status");
	Check(!ParseSessionStatus(200, std::string("{\"active\":false,\"master_account_id\":\"") + kMasterId + "\"}").value,
		"inactive success cannot prove liveness");
	Check(ParseOk(200, R"({"ok":true})").value == true, "default wrap acknowledgement");
	Check(!ParseOk(200, R"({"ok":false})").value, "negative acknowledgement rejected");
	Check(!ParseAuth(200, std::string(kMaxResponseBytes + 1, ' ')).value, "response body byte bound");
}

void TestMeAndEntitlements() {
	auto fixture = Me();
	const auto me = ParseMe(200, Body(fixture));
	Check(me.value && me.value->account.telegramUserId == 123456789 && me.value->account.kzConsentRequired,
		"complete account metadata");
	Check(me.value->devices.size() == 1 && me.value->consents.at("privacy").granted, "devices and consents");
	Check(PremiumAtServerTime(*me.value)->access == PremiumAccess::Expiring, "manual grant is premium");
	Check(PremiumAtServerTime(*me.value)->expiresAtMs == ParseTimestamp(kFuture), "premium deadline uses server time");
	for (const auto source : { "play", "apple", "stripe", "paddle", "promo", "tribute", "manual", "future-source" }) {
		Fields(fixture)["entitlements"] = { Array{ EntitlementValue("premium", source, {}) } };
		Check(PremiumAtServerTime(*ParseMe(200, Body(fixture)).value)->access == PremiumAccess::Perpetual,
			"perpetual grants independent of billing source");
	}
	Fields(fixture)["entitlements"] = { Array{ EntitlementValue("future-kind", "manual", {}) } };
	Check(PremiumAtServerTime(*ParseMe(200, Body(fixture)).value)->access == PremiumAccess::Inactive, "unknown kind cannot grant premium");
	Fields(fixture)["entitlements"] = { Array{ EntitlementValue("premium", "manual", Text(kNow)) } };
	Check(PremiumAtServerTime(*ParseMe(200, Body(fixture)).value)->access == PremiumAccess::Inactive, "expiry boundary exclusive");
	Fields(fixture)["entitlements"] = { Array{} };
	Check(PremiumAtServerTime(*ParseMe(200, Body(fixture)).value)->access == PremiumAccess::Inactive, "authoritative empty array revokes premium");
	Fields(fixture).erase("server_now");
	const auto missingClock = ParseMe(200, Body(fixture));
	Check(missingClock.value && !PremiumAtServerTime(*missingClock.value), "missing server clock cannot revoke offline cache");
	fixture = Me();
	Fields(fixture)["entitlements"] = { Array{ EntitlementValue("premium", "manual", Text("garbage")) } };
	Check(!ParseMe(200, Body(fixture)).value, "bad expiry invalidates snapshot");
	fixture = Me();
	Fields(fixture).erase("entitlements");
	Check(!ParseMe(200, Body(fixture)).value, "missing entitlement array not empty");
	fixture = Me();
	Fields(Fields(fixture)["account"])["telegram_user_id"] = Number("9007199254740992");
	Check(!ParseMe(200, Body(fixture)).value, "Telegram id must be safe exact integer");
}

void TestRequests() {
	const auto login = Request(EncodeAuthRequest("query=public&signature=fixture"));
	Check(ExactInt64(Fields(login).at("bootstrap_version")) == 1 && !Fields(login).contains("mode"), "fresh login requests bootstrap");
	const auto renew = Request(EncodeAuthRequest("fresh-public-fixture", Generation{ kMasterId, kSyncId }));
	Check(std::get<std::string>(Fields(renew).at("mode").value) == "renew"
		&& !Fields(renew).contains("bootstrap_version"), "lookup-only renewal preserves generation");
	Check(!EncodeAuthRequest(""), "reject empty auth material");
	Check(!EncodeAuthRequest(std::string(65537, 'x')), "bound auth material");
	Check(!EncodeAuthRequest("fixture", Generation{ "bad", kSyncId }), "renewal requires valid generation");
	auto encrypted = EncryptedBlob();
	encrypted.ciphertext.resize(16);
	const auto put = Request(EncodePutRequest(encrypted, 0));
	Check(ExactInt64(Fields(put).at("prev_version")) == 0, "new blob CAS version zero");
	Check(!EncodePutRequest(encrypted, -1) && !EncodePutRequest(encrypted, kMaxSafeInteger), "CAS successor cannot overflow safe integer");
	Check(EncodePutRequest(encrypted, kMaxSafeInteger - 1).has_value(), "largest writable CAS version");
	const auto key = std::array<unsigned char, 32>();
	const auto wrap = Request(EncodeDefaultWrapRequest(key));
	Check(std::get<std::string>(Fields(wrap).at("k_master").value) == Base64(32), "default wrap exact base64");
	Check(!EncodeDefaultWrapRequest({}), "reject missing master key");
	const auto device = Request(EncodeDeviceRequest(key, "Windows fixture"));
	Check(std::get<std::string>(Fields(device).at("platform").value) == "windows"
		&& !kWindowsDeviceRegistrationSupported, "never impersonate supported mobile platform");
	Check(!EncodeDeviceRequest(key, std::string(129, 'x')), "device name length bound");
	Check(!EncodeDeviceRequest(key, std::string(5000, '\x80')), "invalid UTF-8 cannot evade allocation bound");
	Check(EncodeDeviceRequest(key, std::string(128, 'x')).has_value(), "device name maximum");
}

void TestMaximumPrivacy() {
	const auto wrapped = WrappedKey();
	const auto salt = Salt();
	const auto upgrade = Request(EncodeUpgradePrivacyRequest(wrapped, salt, wrapped, salt));
	Check(Fields(upgrade).size() == 4, "upgrade sends only four opaque fields");
	Check(std::get<std::string>(Fields(upgrade).at("wrapped_k_master_pw").value) == Base64(72), "password wrap format exact");
	Check(std::get<std::string>(Fields(upgrade).at("wrapped_k_master_recovery").value) == Base64(72), "recovery wrap format exact");
	Check(std::get<std::string>(Fields(upgrade).at("salt_pw").value) == Base64(16), "password salt format exact");
	Check(std::get<std::string>(Fields(upgrade).at("salt_recovery").value) == Base64(16), "recovery salt format exact");
	Check(!EncodeUpgradePrivacyRequest({}, salt, wrapped, salt), "missing password wrap rejected");
	Check(!EncodeUpgradePrivacyRequest(wrapped, {}, wrapped, salt), "missing password salt rejected");
	Check(!EncodeUpgradePrivacyRequest(wrapped, salt, {}, salt), "missing recovery wrap rejected");
	Check(!EncodeUpgradePrivacyRequest(wrapped, salt, wrapped, {}), "missing recovery salt rejected");
	const auto rewrap = Request(EncodePasswordWrapRequest(wrapped, salt, 7));
	Check(Fields(rewrap).size() == 3, "rewrap cannot replace recovery or disclose key");
	Check(ExactInt64(Fields(rewrap).at("prev_wrap_version")) == 7, "rewrap uses wrap CAS version");
	for (const auto invalid : { std::int64_t(-1), std::int64_t(0), kMaxSafeInteger }) {
		Check(!EncodePasswordWrapRequest(wrapped, salt, invalid), "rewrap CAS must have safe positive successor");
	}
	Check(EncodePasswordWrapRequest(wrapped, salt, kMaxSafeInteger - 1).has_value(), "largest safe wrap CAS");
	Check(!EncodePasswordWrapRequest({}, salt, 1), "missing rewrap rejected");
	Check(!EncodePasswordWrapRequest(wrapped, {}, 1), "missing rewrap salt rejected");
	const auto receipt = ParseWrapReceipt(200, R"({"ok":true,"wrap_version":9})");
	Check(receipt.value && receipt.value->wrapVersion == 9, "wrap receipt exact");
	for (const auto body : {
		R"({"ok":true})", R"({"ok":false,"wrap_version":1})",
		R"({"ok":true,"wrap_version":0})", R"({"ok":true,"wrap_version":-1})",
		R"({"ok":true,"wrap_version":1.5})", R"({"ok":true,"wrap_version":9007199254740992})",
	}) {
		Check(!ParseWrapReceipt(200, body).value, "malformed wrap receipt rejected");
	}
	const auto conflict = ParseWrapReceipt(409, R"({"error":{"code":"version_conflict"},"current_wrap_version":11})");
	Check(!conflict.value && conflict.failure.kind == FailureKind::VersionConflict, "wrap conflict preserved");
	Check(conflict.failure.currentWrapVersion == 11 && !conflict.failure.currentVersion, "wrap version never confused with blob version");
	Check(!ParseFailure(409, R"({"error":{"code":"version_conflict"},"current_wrap_version":0})").currentWrapVersion, "zero wrap version invalid");
	Check(ParseWrapReceipt(409, R"({"error":{"code":"not_in_default_mode"}})").failure.kind == FailureKind::Rejected, "mode race requires fresh key fetch");
}

} // namespace

int main() {
	Check(sodium_init() >= 0, "libsodium initialized");
	TestIdentifiersAndTime();
	TestFailures();
	TestKeyAndBase64();
	TestAuthAndBootstrap();
	TestBlobAndReceipts();
	TestMeAndEntitlements();
	TestRequests();
	TestMaximumPrivacy();
	std::cout << "Sync backend checks passed: " << Checks << '\n';
}
