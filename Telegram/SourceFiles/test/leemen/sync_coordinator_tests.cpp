#include "leemen/sync_coordinator.h"

#include <cstdlib>
#include <iostream>
#include <utility>

namespace {

using namespace Leemen::Sync;
auto Checks = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

RemoteRead Absent() {
	return { RemoteReadStatus::Absent, 0, {} };
}

RemoteRead Present(const FilterBlob &blob, std::int64_t version = 1) {
	return { RemoteReadStatus::Present, version, *EncodeFilterBlob(blob) };
}

RemoteRead Present(const ContentBlob &blob, std::int64_t version = 1) {
	return { RemoteReadStatus::Present, version, *EncodeContentBlob(blob) };
}

SyncCoordinator EmptyReady() {
	auto sync = SyncCoordinator();
	const auto requests = sync.pull();
	Check(requests.size() == 2, "pull both halves");
	Check(!sync.projection(), "pair gate closed before either read");
	Check(sync.acceptRead(requests[1].id, Absent()).empty(), "content first waits");
	Check(!sync.projection(), "one half cannot open gate");
	Check(sync.acceptRead(requests[0].id, Absent()).empty(), "empty pair needs no writes");
	Check(sync.projection() && sync.phase() == SyncPhase::Ready, "confirmed absent ready");
	return sync;
}

std::vector<SyncRequest> SubmitHide(SyncCoordinator &sync) {
	auto filter = sync.projection()->filter;
	auto content = sync.projection()->content;
	const auto clock = *NextLamport(filter, content);
	filter.hiddenChatIds["42"] = Register{ "present", clock, "windows", {} };
	return sync.submit(std::move(filter), std::move(content));
}

void FailureAndEpochs() {
	auto sync = EmptyReady();
	const auto reads = sync.pull();
	Check(sync.acceptRead(reads[0].id, {}).empty(), "failed fetch emits no PUT");
	Check(sync.phase() == SyncPhase::Blocked && !sync.projection(), "failed pair fails closed");
	Check(sync.acceptRead(reads[1].id, Absent()).empty(), "late half ignored");
	Check(!sync.projection(), "late half never reopens gate");
	const auto next = sync.pull();
	Check(next.front().id > reads.back().id, "monotonic request generations");
	sync.close();
	Check(sync.acceptRead(next[0].id, Absent()).empty(), "logged-out callback ignored");
	Check(sync.phase() == SyncPhase::Closed, "logout remains closed");
	const auto third = sync.pull();
	Check(third.front().id > next.back().id, "relogin does not reuse callback ids");
	Check(sync.acceptRead(third[0].id, { RemoteReadStatus::Absent, 4, {} }).empty(), "inconsistent absent rejected");
	Check(sync.failure() == SyncFailure::InvalidData, "invalid absence distinct from network");
}

void OrderedWritesAndConflict() {
	auto sync = EmptyReady();
	auto reads = SubmitHide(sync);
	Check(reads.size() == 2 && !sync.projection(), "mutation revalidates before writing");
	Check(sync.pendingMutation(), "mutation retained before network");
	Check(sync.acceptRead(reads[0].id, Absent()).empty(), "mutation requires full pair");
	auto writes = sync.acceptRead(reads[1].id, Absent());
	Check(writes.size() == 1 && writes[0].kind == BlobKind::Content, "addition content first");
	const auto oldWrite = writes[0].id;
	reads = sync.acceptWrite(oldWrite, RemoteWriteStatus::Conflict, 400);
	Check(reads.size() == 2, "CAS conflict rereads both halves");
	Check(sync.acceptWrite(oldWrite, RemoteWriteStatus::Accepted, 1).empty(), "duplicate stale PUT reply ignored");
	auto remoteContent = ContentBlob();
	remoteContent.lamport = 2;
	remoteContent.privateSearchDialogIds["43"] = Register{ "present", 2, "android", {} };
	Check(sync.acceptRead(reads[0].id, Absent()).empty(), "conflict filter waits");
	writes = sync.acceptRead(reads[1].id, Present(remoteContent, 12));
	Check(writes.size() == 1 && writes[0].kind == BlobKind::Filter, "unchanged merged content is not overwritten");
	Check(writes[0].previousVersion == 0, "uses actual read version not conflict hint");
	Check(sync.acceptWrite(writes[0].id, RemoteWriteStatus::Accepted, 1).empty(), "last write completes");
	Check(sync.projection() && !sync.pendingMutation(), "projection published after ordered writes");
	Check(sync.projection()->content.privateSearchDialogIds.contains("43"), "concurrent Android value retained");
	Check(sync.projection()->contentVersion == 12, "untouched half version retained");
}

void RemovalAndFailedSecondWrite() {
	auto sync = EmptyReady();
	auto reads = SubmitHide(sync);
	(void)sync.acceptRead(reads[0].id, Absent());
	auto writes = sync.acceptRead(reads[1].id, Absent());
	writes = sync.acceptWrite(writes[0].id, RemoteWriteStatus::Accepted, 1);
	Check(writes.size() == 1 && writes[0].kind == BlobKind::Filter, "content commit precedes membership");
	(void)sync.acceptWrite(writes[0].id, RemoteWriteStatus::Accepted, 1);
	auto before = *sync.projection();
	auto filter = before.filter;
	auto content = before.content;
	const auto clock = *NextLamport(filter, content);
	filter.hiddenChatIds["42"] = Register{ "removed", clock, "windows", {} };
	content.perChat["42"].clearedAtClock = clock;
	reads = sync.submit(std::move(filter), std::move(content));
	(void)sync.acceptRead(reads[0].id, Present(before.filter));
	writes = sync.acceptRead(reads[1].id, Present(before.content));
	Check(writes.size() == 1 && writes[0].kind == BlobKind::Filter, "removal filter first");
	writes = sync.acceptWrite(writes[0].id, RemoteWriteStatus::Accepted, 2);
	Check(writes.size() == 1 && writes[0].kind == BlobKind::Content, "removal content second");
	(void)sync.acceptWrite(writes[0].id, RemoteWriteStatus::Failed);
	Check(!sync.projection() && sync.pendingMutation(), "partial transaction fails closed and retains mutation");
	Check(sync.pull().size() == 2, "failed transaction retries only after re-read");
}

void CorruptConflictAndAuthorization() {
	for (const auto plaintext : { "broken", "{\"schema_version\":3}" }) {
		auto sync = EmptyReady();
		auto reads = SubmitHide(sync);
		(void)sync.acceptRead(reads[0].id, Absent());
		const auto writes = sync.acceptRead(reads[1].id, Absent());
		reads = sync.acceptWrite(writes[0].id, RemoteWriteStatus::Conflict);
		(void)sync.acceptRead(reads[0].id, Absent());
		Check(sync.acceptRead(reads[1].id, { RemoteReadStatus::Present, 5, plaintext }).empty(), "undecodable conflict never yields PUT");
		Check(sync.phase() == SyncPhase::Blocked && sync.pendingMutation(), "unknown remote retains pending local data");
	}
	auto sync = EmptyReady();
	const auto reads = SubmitHide(sync);
	(void)sync.acceptRead(reads[0].id, Absent());
	auto changed = ContentBlob();
	changed.pin = PinRegister();
	changed.pin->state = "none";
	changed.pin->clock = 8;
	changed.pin->device = "android";
	Check(sync.acceptRead(reads[1].id, Present(changed)).empty(), "PIN epoch change rejects old authorization");
	Check(sync.failure() == SyncFailure::AuthorizationChanged, "PIN change explicit failure");
	Check(sync.pull().empty(), "automatic retry cannot reuse invalidated authorization");
	sync.discardPendingMutation();
	Check(sync.pull().size() == 2, "explicitly discard mutation permits fresh reconciliation");
}

void ConflictBudgetAndBadAcknowledgement() {
	auto sync = EmptyReady();
	auto reads = SubmitHide(sync);
	for (auto attempt = 0; attempt != 4; ++attempt) {
		(void)sync.acceptRead(reads[0].id, Absent());
		const auto writes = sync.acceptRead(reads[1].id, Absent());
		Check(writes.size() == 1, "bounded conflict retry produces one PUT");
		reads = sync.acceptWrite(writes[0].id, RemoteWriteStatus::Conflict);
	}
	Check(reads.empty() && sync.failure() == SyncFailure::ConflictLimit, "conflicts terminate after budget");
	Check(sync.pendingMutation() && !sync.projection(), "conflict exhaustion preserves dirty state and privacy");
	sync = EmptyReady();
	reads = SubmitHide(sync);
	(void)sync.acceptRead(reads[0].id, Absent());
	const auto writes = sync.acceptRead(reads[1].id, Absent());
	Check(sync.acceptWrite(writes[0].id, RemoteWriteStatus::Accepted, 9).empty(), "bad acknowledged version never advances next half");
	Check(sync.failure() == SyncFailure::InvalidData, "nonconsecutive version rejected");
}

void CrashRecovery() {
	auto original = EmptyReady();
	const auto stale = SubmitHide(original);
	const auto checkpoint = original.checkpoint();
	auto restarted = SyncCoordinator();
	Check(restarted.restoreCheckpoint(checkpoint), "restore pending journal");
	Check(!restarted.projection(), "journal is never a trusted remote projection");
	Check(restarted.pendingMutation(), "restart preserves user mutation");
	auto reads = restarted.pull();
	(void)restarted.acceptRead(reads[0].id, Absent());
	auto writes = restarted.acceptRead(reads[1].id, Absent());
	Check(writes.size() == 1 && writes[0].previousVersion == 0, "restored journal revalidates server");
	Check(original.restoreCheckpoint(checkpoint), "restore replaces live coordinator state");
	Check(original.acceptRead(stale[0].id, Absent()).empty(), "restore invalidates previous callbacks");
	auto broken = checkpoint;
	broken.pending->filterVersion = -1;
	Check(!restarted.restoreCheckpoint(std::move(broken)), "reject corrupt journal version");
	Check(!restarted.projection() && !restarted.pendingMutation(), "invalid journal leaves closed gate");
}

void RemoteResetCannotResurrectState() {
	auto sync = SyncCoordinator();
	auto reads = sync.pull();
	(void)sync.acceptRead(reads[0].id, Present(FilterBlob(), 4));
	(void)sync.acceptRead(reads[1].id, Present(ContentBlob(), 7));
	Check(sync.projection(), "established server versions trusted");
	reads = SubmitHide(sync);
	const auto saved = sync.checkpoint();
	(void)sync.acceptRead(reads[0].id, Absent());
	Check(sync.acceptRead(reads[1].id, Absent()).empty(), "server reset emits no resurrection PUT");
	Check(sync.failure() == SyncFailure::InvalidData && sync.pendingMutation(), "reset preserves journal behind closed gate");
	auto restarted = SyncCoordinator();
	Check(restarted.restoreCheckpoint(saved), "restore reset-race journal");
	reads = restarted.pull();
	(void)restarted.acceptRead(reads[0].id, Present(FilterBlob(), 3));
	Check(restarted.acceptRead(reads[1].id, Present(ContentBlob(), 7)).empty(), "nonzero version regression also rejected");
	Check(restarted.failure() == SyncFailure::InvalidData, "persisted version floor survives restart");
	auto ownWrite = EmptyReady();
	reads = SubmitHide(ownWrite);
	(void)ownWrite.acceptRead(reads[0].id, Absent());
	auto writes = ownWrite.acceptRead(reads[1].id, Absent());
	writes = ownWrite.acceptWrite(writes[0].id, RemoteWriteStatus::Accepted, 1);
	Check(ownWrite.checkpoint().pending->contentVersion == 1, "own partial commit raises journal floor");
	reads = ownWrite.acceptWrite(writes[0].id, RemoteWriteStatus::Conflict);
	(void)ownWrite.acceptRead(reads[0].id, Absent());
	(void)ownWrite.acceptRead(reads[1].id, Absent());
	Check(ownWrite.failure() == SyncFailure::InvalidData, "reset after own partial commit stays closed");
}

void NonVisibilityMutations() {
	auto trusted = SyncPair();
	trusted.filter.hiddenChatIds["42"] = { "present", 1, "android", {} };
	trusted.content.perChat["42"].messageState["5"] = { "hidden", 1, "android", {} };
	auto pending = trusted;
	pending.filter.lamport = pending.content.lamport = 2;
	pending.content.privateSearchDialogIds["42"] = { "present", 2, "windows", {} };
	Check(CanRetainTrustedProjection(trusted, pending), "private search sync keeps view open");
	pending.content.settings.pinTimeoutMinutes = IntRegister{ 5, 2, "windows", {} };
	Check(CanRetainTrustedProjection(trusted, pending), "timeout sync keeps current view");
	pending.content.perChat["43"].selfPinned["2"] = { "present", 2, "windows", {} };
	Check(CanRetainTrustedProjection(trusted, pending), "self-pin-only chat does not close view");
	auto unsafe = pending;
	unsafe.filter.hiddenChatIds["43"] = { "present", 2, "windows", {} };
	Check(!CanRetainTrustedProjection(trusted, unsafe), "new membership closes projection");
	unsafe = pending;
	unsafe.filter.chatsOffModeVisible.push_back("42");
	Check(!CanRetainTrustedProjection(trusted, unsafe), "OFF visibility change closes projection");
	unsafe = pending;
	unsafe.content.perChat["42"].messageState["5"] = { "exposed", 2, "windows", {} };
	Check(!CanRetainTrustedProjection(trusted, unsafe), "message visibility change closes projection");
	unsafe = pending;
	unsafe.content.perChat["43"].clearedAtClock = 2;
	Check(!CanRetainTrustedProjection(trusted, unsafe), "clear barrier closes projection");
	unsafe = pending;
	unsafe.content.pin = PinRegister();
	Check(!CanRetainTrustedProjection(trusted, unsafe), "PIN epoch closes projection");
	unsafe = pending;
	unsafe.content.settings.allowScreenshots = BoolRegister{ false, 2, "windows", {} };
	Check(!CanRetainTrustedProjection(trusted, unsafe), "capture setting closes projection");
	unsafe = pending;
	unsafe.content.unknownFields["future_visibility"].value = true;
	Check(!CanRetainTrustedProjection(trusted, unsafe), "future semantics close projection");
	unsafe = pending;
	unsafe.content.perChat["43"].unknownFields["future"].value = true;
	Check(!CanRetainTrustedProjection(trusted, unsafe), "future per-chat semantics retained in comparison");
}

} // namespace

int main() {
	FailureAndEpochs();
	OrderedWritesAndConflict();
	RemovalAndFailedSecondWrite();
	CorruptConflictAndAuthorization();
	ConflictBudgetAndBadAcknowledgement();
	CrashRecovery();
	RemoteResetCannotResurrectState();
	NonVisibilityMutations();
	std::cout << Checks << " sync coordinator checks passed\n";
}
