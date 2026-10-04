#include "leemen/sync_session_snapshot.h"
#include "leemen/private_message_policy.h"

#include <cstdlib>
#include <iostream>
#include <limits>

namespace {

using namespace Leemen::Sync;
using Object = JsonValue::Object;
auto Checks = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

SessionSnapshot Sample(bool pending = false) {
	auto result = SessionSnapshot{
		9007199254740993ULL,
		{ "01234567-89ab-4cde-8fab-0123456789ab", "abcdef01-2345-4678-89ab-cdef01234567" },
		true, std::string(64, 'a'), LocalResetState::None, {} };
	if (pending) {
		auto pair = SyncPair();
		pair.filter.lamport = pair.content.lamport = 9007199254740993LL;
		pair.filterVersion = 14;
		pair.contentVersion = 19;
		pair.filter.hiddenChatIds["42"] = Register{ "present", 18, "windows", {} };
		pair.content.perChat["42"].messageState["7"] = Register{ "hidden", 19, "windows", {} };
		pair.content.unknownFields["future"] = JsonValue{ JsonNumber{ "1e400" } };
		result.checkpoint.pending = std::move(pair);
		result.checkpoint.authorizedPin = PinRegister{ "none", {}, {}, {}, 16, "android", {} };
		result.checkpoint.filterVersionFloor = 14;
		result.checkpoint.contentVersionFloor = 19;
	}
	return result;
}

std::string Encode(const SessionSnapshot &snapshot) {
	const auto result = EncodeSessionSnapshot(snapshot);
	Check(result.has_value(), "valid snapshot encoded");
	return *result;
}

JsonValue Fixture() {
	return *ParseJson(Encode(Sample(true)), { 1024 * 1024, 64, 131072 }).value;
}

bool Readable(const JsonValue &value) {
	const auto encoded = EncodeJson(value, { 1024 * 1024, 64, 131072 });
	return encoded && ReadSessionSnapshot(*encoded, Sample().telegramUserId).has_value();
}

void RoundTrips() {
	for (const auto reset : { LocalResetState::None, LocalResetState::Pending, LocalResetState::Confirmed }) {
		for (const auto pending : { false, true }) {
			auto original = Sample(pending);
			original.reset = reset;
			const auto bytes = Encode(original);
			const auto restored = ReadSessionSnapshot(bytes, original.telegramUserId);
			Check(restored.has_value(), "restart record accepted");
			Check(restored->telegramUserId == original.telegramUserId, "opaque user id exact above double range");
			Check(restored->generation == original.generation, "account generation preserved");
			Check(restored->maximum && restored->keyFingerprint == original.keyFingerprint, "key binding retained");
			Check(restored->reset == reset, "pending and confirmed quarantine survive restart independently");
			Check(bool(restored->checkpoint.pending) == pending, "pending presence retained");
			Check(restored->checkpoint.filterVersionFloor == original.checkpoint.filterVersionFloor
				&& restored->checkpoint.contentVersionFloor == original.checkpoint.contentVersionFloor,
				"observed floors retained independently of pending presence");
			if (pending) {
				const auto &before = *original.checkpoint.pending;
				const auto &after = *restored->checkpoint.pending;
				Check(before.filter == after.filter && before.content == after.content, "unacknowledged content is lossless");
				Check(before.filterVersion == after.filterVersion && before.contentVersion == after.contentVersion,
					"CAS lower bounds retained during quarantine");
				Check(original.checkpoint.authorizedPin == restored->checkpoint.authorizedPin, "old PIN authorization retained");
			}
			Check(bytes.find("token") == std::string::npos && bytes.find("master_key") == std::string::npos,
				"snapshot contains no credentials");
			Check(!ReadSessionSnapshot(bytes, original.telegramUserId + 1), "other Telegram account cannot restore journal");
		}
	}
	auto bootstrap = Sample();
	bootstrap.keyFingerprint.reset();
	bootstrap.maximum = false;
	Check(ReadSessionSnapshot(Encode(bootstrap), bootstrap.telegramUserId).has_value(), "first auth may precede key fingerprint");
	bootstrap.reset = LocalResetState::Pending;
	Check(ReadSessionSnapshot(Encode(bootstrap), bootstrap.telegramUserId)->reset == LocalResetState::Pending,
		"lost-secret reset can quarantine an account before any master key was obtained");
}

void AccountDeletionQuarantine() {
	for (const auto maximum : { false, true }) {
		for (const auto dirty : { false, true }) {
			for (const auto reset : { LocalResetState::None, LocalResetState::Pending }) {
				auto original = Sample(dirty);
				original.maximum = maximum;
				original.reset = reset;
				original.accountDeletePending = true;
				const auto serialized = Encode(original);
				const auto restored = ReadSessionSnapshot(serialized, original.telegramUserId);
				Check(restored && restored->accountDeletePending, "pending account deletion survives process restart");
				Check(restored->reset == reset && restored->maximum == maximum,
					"whole-account quarantine preserves preceding reset and privacy mode");
				Check(restored->generation == original.generation && restored->keyFingerprint == original.keyFingerprint,
					"pending deletion remains bound to the old generation and key");
				Check(restored->checkpoint.filterVersionFloor == original.checkpoint.filterVersionFloor
					&& restored->checkpoint.contentVersionFloor == original.checkpoint.contentVersionFloor,
					"deletion quarantine preserves acknowledged version floors");
				auto coordinator = SyncCoordinator();
				Check(coordinator.restoreCheckpoint(restored->checkpoint), "quarantined checkpoint remains restorable");
				Check(!coordinator.projection() && bool(coordinator.pendingMutation()) == dirty,
					"restart stays closed and retains unacknowledged private mutations");
				if (dirty) {
					Check(coordinator.pendingMutation()->filter == original.checkpoint.pending->filter
						&& coordinator.pendingMutation()->content == original.checkpoint.pending->content,
						"whole-account deletion never silently discards pending data before acknowledgement");
				}
				Check(!ReadSessionSnapshot(serialized, original.telegramUserId + 1),
					"deletion marker cannot be transferred to another Telegram account");
			}
		}
	}
	auto noSecret = Sample();
	noSecret.keyFingerprint.reset();
	noSecret.accountDeletePending = true;
	Check(ReadSessionSnapshot(Encode(noSecret), noSecret.telegramUserId)->accountDeletePending,
		"forgotten-secret deletion can be quarantined before obtaining the master key");
	const auto legacy = ReadSessionSnapshot(Encode(Sample()), Sample().telegramUserId);
	Check(legacy && !legacy->accountDeletePending, "legacy marker absence does not invent a deletion intent");
	for (const auto &invalid : std::vector<JsonValue>{ JsonValue{ nullptr }, JsonValue{ true },
		JsonValue{ false }, JsonValue{ JsonNumber{ "1" } }, JsonValue{ std::string() },
		JsonValue{ std::string("confirmed") }, JsonValue{ std::string("none") },
		JsonValue{ std::string("Pending") }, JsonValue{ std::string("pending ") } }) {
		auto value = Fixture();
		std::get<Object>(value.value)["account_delete"] = invalid;
		Check(!Readable(value), "invalid account deletion marker fails closed instead of releasing quarantine");
	}
	auto duplicate = Encode(noSecret);
	duplicate.insert(1, "\"account_delete\":\"pending\",");
	Check(!ReadSessionSnapshot(duplicate, noSecret.telegramUserId), "duplicate deletion marker is rejected");
	noSecret.reset = LocalResetState::Confirmed;
	Check(!EncodeSessionSnapshot(noSecret), "conflicting confirmed reset cannot release pending whole-account deletion");
	auto conflict = Fixture();
	std::get<Object>(conflict.value)["account_delete"] = JsonValue{ std::string("pending") };
	std::get<Object>(conflict.value)["reset"] = JsonValue{ std::string("confirmed") };
	Check(!Readable(conflict), "reader rejects contradictory destructive-operation acknowledgements");
}

void InvalidRecords() {
	const auto badReset = std::vector<JsonValue>{
		JsonValue{ nullptr }, JsonValue{ true }, JsonValue{ std::string("none") },
		JsonValue{ std::string("done") }, JsonValue{ JsonNumber{ "1" } },
	};
	for (const auto &reset : badReset) {
		auto value = Fixture();
		std::get<Object>(value.value)["reset"] = reset;
		Check(!Readable(value), "unknown or malformed reset state cannot release quarantine");
	}
	for (const auto *field : { "version", "telegram_user_id", "master_account_id", "sync_account_id", "maximum", "key_fingerprint" }) {
		auto value = Fixture();
		std::get<Object>(value.value).erase(field);
		Check(!Readable(value), "required journal binding missing rejected");
	}
	for (const auto &fingerprint : { std::string(63, 'a'), std::string(65, 'a'), std::string(64, 'A'), std::string(64, 'x') }) {
		auto value = Fixture();
		std::get<Object>(value.value)["key_fingerprint"] = JsonValue{ fingerprint };
		Check(!Readable(value), "fingerprint must be exact lowercase SHA256 hex");
	}
	for (const auto *field : { "filter", "content", "filter_version", "content_version", "authorized" }) {
		auto value = Fixture();
		auto &pending = std::get<Object>(std::get<Object>(value.value).at("pending").value);
		pending.erase(field);
		Check(!Readable(value), "partial pending pair rejected");
	}
	for (const auto token : { "-1", "1.5", "9007199254740992", "1e999" }) {
		auto value = Fixture();
		auto &pending = std::get<Object>(std::get<Object>(value.value).at("pending").value);
		pending["content_version"] = JsonValue{ JsonNumber{ token } };
		Check(!Readable(value), "unsafe CAS journal version rejected");
		for (const auto *field : { "filter_version_floor", "content_version_floor" }) {
			auto floor = Fixture();
			std::get<Object>(floor.value)[field] = JsonValue{ JsonNumber{ token } };
			Check(!Readable(floor), "unsafe observed floor rejected even with valid pending versions");
		}
	}
	for (const auto *field : { "filter_version_floor", "content_version_floor" }) {
		auto value = Fixture();
		std::get<Object>(value.value).erase(field);
		Check(!Readable(value), "partial observed version pair rejected");
	}
	auto numericId = Fixture();
	std::get<Object>(numericId.value)["telegram_user_id"] = JsonValue{ JsonNumber{ "9007199254740993" } };
	Check(!Readable(numericId), "numeric identity rejected instead of losing precision");
	Check(!ReadSessionSnapshot("{}", 1), "empty object is not a valid safe snapshot");
	Check(!ReadSessionSnapshot("", 1), "empty input is not a fabricated account");
	Check(!ReadSessionSnapshot(std::string(2 * 1024 * 1024 + 1, ' '), 1), "oversized record bounded");
	const auto valid = Encode(Sample());
	Check(!ReadSessionSnapshot(valid, 0), "zero user id rejected");
	auto duplicate = valid;
	duplicate.insert(1, "\"reset\":\"pending\",\"reset\":\"confirmed\",");
	Check(!ReadSessionSnapshot(duplicate, Sample().telegramUserId), "duplicate reset keys cannot downgrade quarantine");
	auto invalid = Sample(true);
	invalid.keyFingerprint.reset();
	Check(!EncodeSessionSnapshot(invalid), "writer refuses unbound dirty journal");
	invalid = Sample();
	invalid.reset = LocalResetState(99);
	Check(!EncodeSessionSnapshot(invalid), "writer rejects unknown enum values");
	invalid = Sample();
	invalid.checkpoint.authorizedPin = PinRegister{ "none", {}, {}, {}, 0, "windows", {} };
	Check(!EncodeSessionSnapshot(invalid), "orphan authorization is not silently discarded");
}

void ConfirmedCleanup() {
	auto snapshot = Sample(true);
	snapshot.reset = LocalResetState::Confirmed;
	auto restored = ReadSessionSnapshot(Encode(snapshot), snapshot.telegramUserId);
	auto coordinator = SyncCoordinator();
	Check(coordinator.restoreCheckpoint(std::move(restored->checkpoint)), "confirmed reset still holds dirty data for adapter cleanup");
	Check(coordinator.pendingMutation() && !coordinator.projection(), "restored pending state never starts unlocked");
	coordinator.close();
	Check(!coordinator.pendingMutation() && !coordinator.projection(), "explicit confirmed local cleanup discards old queue");
	Check(!coordinator.checkpoint().authorizedPin, "old PIN authorization erased together with old journal");
	Check(!coordinator.checkpoint().filterVersionFloor && !coordinator.checkpoint().contentVersionFloor,
		"explicit confirmed cleanup releases old-generation version floors");
}

void CommittedFloors() {
	auto snapshot = Sample();
	auto coordinator = SyncCoordinator();
	auto reads = coordinator.pull();
	Check(coordinator.acceptRead(reads[0].id,
		{ RemoteReadStatus::Present, 4, *EncodeFilterBlob(FilterBlob()) }).empty(), "first committed half waits");
	Check(coordinator.acceptRead(reads[1].id,
		{ RemoteReadStatus::Present, 7, *EncodeContentBlob(ContentBlob()) }).empty(), "committed pair accepted");
	snapshot.checkpoint = coordinator.checkpoint();
	Check(!snapshot.checkpoint.pending && snapshot.checkpoint.filterVersionFloor == 4
		&& snapshot.checkpoint.contentVersionFloor == 7, "clean checkpoint retains both observed floors");
	for (const auto &pair : { std::pair{ 0, 0 }, std::pair{ 3, 7 }, std::pair{ 4, 6 } }) {
		const auto restored = ReadSessionSnapshot(Encode(snapshot), snapshot.telegramUserId);
		auto restarted = SyncCoordinator();
		Check(restarted.restoreCheckpoint(restored->checkpoint), "clean checkpoint restored after crash");
		Check(!restarted.projection(), "floor-only restore is not a trusted projection");
		reads = restarted.pull();
		Check(restarted.acceptRead(reads[0].id, { pair.first ? RemoteReadStatus::Present : RemoteReadStatus::Absent,
			pair.first, pair.first ? *EncodeFilterBlob(FilterBlob()) : std::string() }).empty(), "regressed first half waits");
		Check(restarted.acceptRead(reads[1].id, { pair.second ? RemoteReadStatus::Present : RemoteReadStatus::Absent,
			pair.second, pair.second ? *EncodeContentBlob(ContentBlob()) : std::string() }).empty(), "regression never causes writes");
		Check(restarted.failure() == SyncFailure::InvalidData && !restarted.projection(),
			"clean restart rejects absence or regression of either half");
	}
	auto filter = coordinator.projection()->filter;
	auto content = coordinator.projection()->content;
	Check(NextLamport(filter, content) == 1, "local mutation increments both document clocks");
	filter.hiddenChatIds["42"] = Register{ "present", 1, "windows", {} };
	reads = coordinator.submit(filter, content);
	Check(coordinator.acceptRead(reads[0].id,
		{ RemoteReadStatus::Present, 4, *EncodeFilterBlob(FilterBlob()) }).empty(), "mutation validates filter");
	auto writes = coordinator.acceptRead(reads[1].id,
		{ RemoteReadStatus::Present, 7, *EncodeContentBlob(ContentBlob()) });
	Check(writes.size() == 1 && writes[0].kind == BlobKind::Content, "content acknowledgement comes first");
	writes = coordinator.acceptWrite(writes[0].id, RemoteWriteStatus::Accepted, 8);
	Check(writes.size() == 1 && writes[0].kind == BlobKind::Filter, "filter acknowledgement comes last");
	Check(coordinator.acceptWrite(writes[0].id, RemoteWriteStatus::Accepted, 5).empty(), "last write completes cleanly");
	snapshot.checkpoint = coordinator.checkpoint();
	Check(!snapshot.checkpoint.pending && snapshot.checkpoint.filterVersionFloor == 5
		&& snapshot.checkpoint.contentVersionFloor == 8, "both accepted PUT floors survive clearing pending");
	const auto restored = ReadSessionSnapshot(Encode(snapshot), snapshot.telegramUserId);
	Check(restored->checkpoint.filterVersionFloor == 5 && restored->checkpoint.contentVersionFloor == 8,
		"own clean commit floors survive serialized crash recovery");
	coordinator.discardPendingMutation();
	Check(coordinator.checkpoint().filterVersionFloor == 5 && coordinator.checkpoint().contentVersionFloor == 8,
		"discarding local changes cannot erase remote reset protection");
	auto legacy = Fixture();
	std::get<Object>(legacy.value)["version"] = JsonValue{ JsonNumber{ "1" } };
	std::get<Object>(legacy.value).erase("filter_version_floor");
	std::get<Object>(legacy.value).erase("content_version_floor");
	const auto migrated = ReadSessionSnapshot(*EncodeJson(legacy), snapshot.telegramUserId);
	Check(migrated && migrated->checkpoint.filterVersionFloor == 14 && migrated->checkpoint.contentVersionFloor == 19,
		"older dirty checkpoint conservatively derives observed floors from pending versions");
	snapshot.keyFingerprint.reset();
	Check(!EncodeSessionSnapshot(snapshot), "clean observed floors also require a master-key binding");
}

void CachedBaseline() {
	auto snapshot = Sample();
	auto pair = SyncPair();
	pair.filterVersion = 4;
	pair.contentVersion = 7;
	pair.filter.hiddenChatIds["42"] = { "present", 3, "android", {} };
	pair.content.perChat["42"].messageState["5"] = { "hidden", 3, "android", {} };
	pair.content.privateSearchDialogIds["43"] = { "present", 3, "android", {} };
	snapshot.checkpoint.confirmed = pair;
	snapshot.checkpoint.filterVersionFloor = 4;
	snapshot.checkpoint.contentVersionFloor = 7;
	const auto bytes = Encode(snapshot);
	const auto restored = ReadSessionSnapshot(bytes, snapshot.telegramUserId);
	Check(restored && restored->checkpoint.confirmed, "confirmed cache survives offline restart");
	Check(restored->checkpoint.confirmed->filter == pair.filter
		&& restored->checkpoint.confirmed->content == pair.content,
		"cached membership and access comparison preserve the exact committed pair");
	auto coordinator = SyncCoordinator();
	Check(coordinator.restoreCheckpoint(restored->checkpoint), "cached checkpoint restored closed");
	Check(coordinator.cachedProjection() && !coordinator.projection(), "cache does not grant fresh mutation authority");
	Check(Leemen::PrivateSearchOnly(&coordinator.cachedProjection()->content, 43)
		&& !coordinator.cachedProjection()->filter.hiddenChatIds.contains("43"),
		"key-bound offline snapshot retains private recents for an ordinary chat");
	Check(!ReadSessionSnapshot(bytes, snapshot.telegramUserId + 1), "cache cannot move to another Telegram user");
	auto legacy = *ParseJson(bytes).value;
	std::get<Object>(legacy.value)["version"] = JsonValue{ JsonNumber{ "1" } };
	Check(!Readable(legacy), "old schema cannot smuggle a trusted baseline");
	std::get<Object>(legacy.value).erase("confirmed");
	const auto old = ReadSessionSnapshot(*EncodeJson(legacy), snapshot.telegramUserId);
	Check(old && !old->checkpoint.confirmed, "old records remain valid without granting offline trust");
	for (const auto reset : { LocalResetState::Pending, LocalResetState::Confirmed }) {
		auto unsafe = snapshot;
		unsafe.reset = reset;
		Check(!EncodeSessionSnapshot(unsafe), "destructive reset marker cannot retain usable baseline");
	}
	auto unsafe = snapshot;
	unsafe.accountDeletePending = true;
	Check(!EncodeSessionSnapshot(unsafe), "account deletion marker cannot retain usable baseline");
	unsafe = snapshot;
	unsafe.keyFingerprint.reset();
	Check(!EncodeSessionSnapshot(unsafe), "cache requires key binding even before mutations");
	for (const auto *field : { "filter", "content", "filter_version", "content_version" }) {
		auto corrupt = *ParseJson(bytes).value;
		std::get<Object>(std::get<Object>(corrupt.value).at("confirmed").value).erase(field);
		Check(!Readable(corrupt), "partial cached pair is rejected");
	}
	unsafe = snapshot;
	unsafe.checkpoint.confirmed->filterVersion = 5;
	Check(!EncodeSessionSnapshot(unsafe), "cached version cannot exceed acknowledged durable floor");
	unsafe = snapshot;
	unsafe.checkpoint.confirmed->contentVersion = -1;
	Check(!EncodeSessionSnapshot(unsafe), "negative cached version rejected");
	unsafe = snapshot;
	unsafe.checkpoint.contentVersionFloor = 8;
	Check(EncodeSessionSnapshot(unsafe).has_value(), "partial accepted write may advance floor beyond the previous full baseline");
	auto empty = Sample();
	empty.checkpoint.confirmed = SyncPair();
	Check(ReadSessionSnapshot(Encode(empty), empty.telegramUserId)->checkpoint.confirmed.has_value(),
		"conclusively empty remote pair still marks a returning install as synced");
	empty.keyFingerprint.reset();
	Check(!EncodeSessionSnapshot(empty), "empty cache still requires master-key binding");
}

void LocalCheckpointBudget() {
	auto snapshot = Sample();
	auto pair = SyncPair();
	pair.filterVersion = pair.contentVersion = 1;
	pair.filter.unknownFields["payload"] = JsonValue{ std::string(261900, 'x') };
	pair.content.unknownFields["payload"] = JsonValue{ std::string(261900, 'y') };
	Check(EncodeFilterBlob(pair.filter).has_value() && EncodeContentBlob(pair.content).has_value(),
		"large individual blobs stay within remote schema bounds");
	snapshot.checkpoint.confirmed = pair;
	snapshot.checkpoint.pending = pair;
	snapshot.checkpoint.filterVersionFloor = snapshot.checkpoint.contentVersionFloor = 1;
	const auto bytes = Encode(snapshot);
	Check(bytes.size() > 1024 * 1024, "baseline and pending pair can exceed the remote aggregate budget");
	Check(ReadSessionSnapshot(bytes, snapshot.telegramUserId).has_value(), "local four-blob checkpoint remains restorable");
	Check(!ParseJson(bytes, { 2 * 1024 * 1024, 64, 524288 }).value,
		"remote JSON budget cannot opt into larger checkpoint allocations implicitly");
	const auto local = JsonLimits{ 2 * 1024 * 1024, 64, 524288, JsonBudget::LocalCheckpoint };
	auto oversized = *ParseJson(bytes, local).value;
	auto &confirmed = std::get<Object>(std::get<Object>(oversized.value).at("confirmed").value);
	std::get<Object>(confirmed.at("filter").value)["payload"] = JsonValue{ std::string(kMaxBlobPlaintextBytes + 1, 'x') };
	const auto encoded = EncodeJson(oversized, local);
	Check(encoded && !ReadSessionSnapshot(*encoded, snapshot.telegramUserId),
		"larger local record budget never expands an individual remote blob bound");
	auto deep = Sample();
	auto nested = JsonValue{ nullptr };
	for (auto i = 0; i != 63; ++i) {
		nested = JsonValue{ JsonValue::Array{ std::move(nested) } };
	}
	deep.checkpoint.confirmed = SyncPair();
	deep.checkpoint.confirmed->filter.unknownFields["nested"] = std::move(nested);
	Check(EncodeFilterBlob(deep.checkpoint.confirmed->filter).has_value(),
		"remote blob at maximum standalone depth is valid");
	Check(ReadSessionSnapshot(Encode(deep), deep.telegramUserId).has_value(),
		"local journal accounts for wrapper depth around independently bounded blobs");
}

} // namespace

int main() {
	RoundTrips();
	AccountDeletionQuarantine();
	InvalidRecords();
	ConfirmedCleanup();
	CommittedFloors();
	CachedBaseline();
	LocalCheckpointBudget();
	std::cout << "Leemen sync session snapshot: " << Checks << " checks passed\n";
}
