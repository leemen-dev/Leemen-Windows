#include "leemen/sync_session_snapshot.h"

#include <algorithm>

namespace Leemen::Sync {
namespace {

constexpr auto kSnapshotLimits = JsonLimits{ 1024 * 1024, 64, 131072 };

const JsonValue *Field(const JsonValue &value, const char *key) {
	const auto object = std::get_if<JsonValue::Object>(&value.value);
	if (!object) {
		return nullptr;
	}
	const auto i = object->find(key);
	return i == object->end() ? nullptr : &i->second;
}

std::optional<std::string> StringField(const JsonValue &value, const char *key) {
	const auto field = Field(value, key);
	const auto string = field ? std::get_if<std::string>(&field->value) : nullptr;
	return string ? std::make_optional(*string) : std::nullopt;
}

JsonValue Number(std::int64_t value) {
	return { JsonNumber{ std::to_string(value) } };
}

bool ValidFingerprint(const std::string &value) {
	return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char ch) {
		return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
	});
}

bool Valid(const SessionSnapshot &snapshot) {
	auto coordinator = SyncCoordinator();
	return snapshot.telegramUserId
		&& Backend::CanonicalUuid(snapshot.generation.masterAccountId)
		&& Backend::CanonicalUuid(snapshot.generation.syncAccountId)
		&& (!snapshot.keyFingerprint || ValidFingerprint(*snapshot.keyFingerprint))
		&& ((!snapshot.checkpoint.pending
			&& !snapshot.checkpoint.filterVersionFloor
			&& !snapshot.checkpoint.contentVersionFloor) || snapshot.keyFingerprint)
		&& (snapshot.reset == LocalResetState::None
			|| snapshot.reset == LocalResetState::Pending
			|| snapshot.reset == LocalResetState::Confirmed)
		&& coordinator.restoreCheckpoint(snapshot.checkpoint);
}

} // namespace

std::optional<std::string> EncodeSessionSnapshot(const SessionSnapshot &snapshot) {
	if (!Valid(snapshot)) {
		return std::nullopt;
	}
	const auto &checkpoint = snapshot.checkpoint;
	auto object = JsonValue::Object{
		{ "version", Number(1) },
		{ "telegram_user_id", JsonValue{ std::to_string(snapshot.telegramUserId) } },
		{ "master_account_id", JsonValue{ *Backend::CanonicalUuid(snapshot.generation.masterAccountId) } },
		{ "sync_account_id", JsonValue{ *Backend::CanonicalUuid(snapshot.generation.syncAccountId) } },
		{ "maximum", JsonValue{ snapshot.maximum } },
		{ "filter_version_floor", Number(std::max(checkpoint.filterVersionFloor,
			checkpoint.pending ? checkpoint.pending->filterVersion : std::int64_t(0))) },
		{ "content_version_floor", Number(std::max(checkpoint.contentVersionFloor,
			checkpoint.pending ? checkpoint.pending->contentVersion : std::int64_t(0))) },
	};
	if (snapshot.keyFingerprint) {
		object.emplace("key_fingerprint", JsonValue{ *snapshot.keyFingerprint });
	}
	if (snapshot.reset != LocalResetState::None) {
		object.emplace("reset", JsonValue{ std::string(
			snapshot.reset == LocalResetState::Confirmed ? "confirmed" : "pending") });
	}
	if (checkpoint.pending) {
		const auto filter = EncodeFilterBlob(checkpoint.pending->filter);
		const auto content = EncodeContentBlob(checkpoint.pending->content);
		auto authorized = ContentBlob();
		authorized.pin = checkpoint.authorizedPin;
		const auto pin = EncodeContentBlob(authorized);
		if (!filter || !content || !pin) {
			return std::nullopt;
		}
		object.emplace("pending", JsonValue{ JsonValue::Object{
			{ "filter", *ParseJson(*filter).value },
			{ "content", *ParseJson(*content).value },
			{ "filter_version", Number(checkpoint.pending->filterVersion) },
			{ "content_version", Number(checkpoint.pending->contentVersion) },
			{ "authorized", *ParseJson(*pin).value },
		} });
	}
	return EncodeJson(JsonValue{ std::move(object) }, kSnapshotLimits);
}

std::optional<SessionSnapshot> ReadSessionSnapshot(
		std::string_view serialized,
		std::uint64_t expectedTelegramUserId) {
	const auto root = ParseJson(serialized, kSnapshotLimits);
	if (!root.value || !expectedTelegramUserId) {
		return std::nullopt;
	}
	const auto &value = *root.value;
	const auto version = Field(value, "version");
	const auto telegram = StringField(value, "telegram_user_id");
	const auto master = StringField(value, "master_account_id");
	const auto sync = StringField(value, "sync_account_id");
	const auto mode = Field(value, "maximum");
	const auto maximum = mode ? std::get_if<bool>(&mode->value) : nullptr;
	const auto fingerprint = StringField(value, "key_fingerprint");
	const auto reset = StringField(value, "reset");
	if (!version || ExactInt64(*version) != 1
		|| !telegram || *telegram != std::to_string(expectedTelegramUserId)
		|| !master || !Backend::CanonicalUuid(*master)
		|| !sync || !Backend::CanonicalUuid(*sync) || !maximum
		|| (Field(value, "key_fingerprint") && !fingerprint)
		|| (Field(value, "reset") && (!reset || (*reset != "pending" && *reset != "confirmed")))) {
		return std::nullopt;
	}
	auto result = SessionSnapshot{ expectedTelegramUserId,
		{ *Backend::CanonicalUuid(*master), *Backend::CanonicalUuid(*sync) },
		*maximum, fingerprint, !reset ? LocalResetState::None
			: (*reset == "confirmed") ? LocalResetState::Confirmed : LocalResetState::Pending, {} };
	const auto filterFloor = Field(value, "filter_version_floor");
	const auto contentFloor = Field(value, "content_version_floor");
	if (filterFloor || contentFloor) {
		const auto f = filterFloor ? ExactInt64(*filterFloor) : std::nullopt;
		const auto c = contentFloor ? ExactInt64(*contentFloor) : std::nullopt;
		if (!f || !c) {
			return std::nullopt;
		}
		result.checkpoint.filterVersionFloor = *f;
		result.checkpoint.contentVersionFloor = *c;
	}
	if (const auto pending = Field(value, "pending")) {
		const auto filter = Field(*pending, "filter");
		const auto content = Field(*pending, "content");
		const auto filterVersion = Field(*pending, "filter_version");
		const auto contentVersion = Field(*pending, "content_version");
		const auto authorized = Field(*pending, "authorized");
		if (!filter || !content || !filterVersion || !contentVersion || !authorized) {
			return std::nullopt;
		}
		const auto f = EncodeJson(*filter);
		const auto c = EncodeJson(*content);
		const auto a = EncodeJson(*authorized);
		const auto fv = ExactInt64(*filterVersion);
		const auto cv = ExactInt64(*contentVersion);
		if (!f || !c || !a || !fv || !cv) {
			return std::nullopt;
		}
		auto decodedFilter = ReadFilterBlob(*f);
		auto decodedContent = ReadContentBlob(*c);
		auto decodedAuthorized = ReadContentBlob(*a);
		if (!decodedFilter.blob || !decodedContent.blob || !decodedAuthorized.blob) {
			return std::nullopt;
		}
		result.checkpoint.pending = SyncPair{ std::move(*decodedFilter.blob),
			std::move(*decodedContent.blob), *fv, *cv };
		result.checkpoint.authorizedPin = std::move(decodedAuthorized.blob->pin);
		if (!filterFloor && !contentFloor) {
			result.checkpoint.filterVersionFloor = *fv;
			result.checkpoint.contentVersionFloor = *cv;
		}
	}
	return Valid(result) ? std::make_optional(std::move(result)) : std::nullopt;
}

} // namespace Leemen::Sync
