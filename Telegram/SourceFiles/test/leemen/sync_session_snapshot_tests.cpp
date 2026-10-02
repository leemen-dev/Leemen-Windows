#include "leemen/sync_session_snapshot.h"

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
	Check(!ReadSessionSnapshot(std::string(1024 * 1024 + 1, ' '), 1), "oversized record bounded");
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
	for (const auto pair : { std::pair{ 0, 0 }, std::pair{ 3, 7 }, std::pair{ 4, 6 } }) {
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
	std::get<Object>(legacy.value).erase("filter_version_floor");
	std::get<Object>(legacy.value).erase("content_version_floor");
	const auto migrated = ReadSessionSnapshot(*EncodeJson(legacy), snapshot.telegramUserId);
	Check(migrated && migrated->checkpoint.filterVersionFloor == 14 && migrated->checkpoint.contentVersionFloor == 19,
		"older dirty checkpoint conservatively derives observed floors from pending versions");
	snapshot.keyFingerprint.reset();
	Check(!EncodeSessionSnapshot(snapshot), "clean observed floors also require a master-key binding");
}

} // namespace

int main() {
	RoundTrips();
	InvalidRecords();
	ConfirmedCleanup();
	CommittedFloors();
	std::cout << "Leemen sync session snapshot: " << Checks << " checks passed\n";
}
