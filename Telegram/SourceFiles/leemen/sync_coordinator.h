#pragma once

#include "leemen/sync_blob.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace Leemen::Sync {

enum class BlobKind { Filter, Content };
enum class SyncOperation { Read, Write };
enum class SyncPhase { Closed, Reading, Ready, Writing, Blocked };
enum class SyncFailure {
	None,
	Transport,
	InvalidData,
	UnsupportedSchema,
	ConflictLimit,
	AuthorizationChanged,
};

struct SyncPair {
	FilterBlob filter;
	ContentBlob content;
	std::int64_t filterVersion = 0;
	std::int64_t contentVersion = 0;
};

[[nodiscard]] bool CanRetainTrustedProjection(
	const SyncPair &trusted,
	const SyncPair &pending);

struct SyncCheckpoint {
	std::optional<SyncPair> pending;
	std::optional<PinRegister> authorizedPin;
};

struct SyncRequest {
	std::uint64_t id = 0;
	BlobKind kind = BlobKind::Filter;
	SyncOperation operation = SyncOperation::Read;
	std::int64_t previousVersion = 0;
	std::optional<std::string> plaintext;
};

enum class RemoteReadStatus { Present, Absent, Failed };
struct RemoteRead {
	RemoteReadStatus status = RemoteReadStatus::Failed;
	std::int64_t version = 0;
	std::string plaintext;
};
enum class RemoteWriteStatus { Accepted, Conflict, Failed };

class SyncCoordinator final {
public:
	[[nodiscard]] SyncPhase phase() const;
	[[nodiscard]] SyncFailure failure() const;
	[[nodiscard]] const SyncPair *projection() const;
	[[nodiscard]] const SyncPair *pendingMutation() const;
	[[nodiscard]] SyncCheckpoint checkpoint() const;
	bool restoreCheckpoint(SyncCheckpoint checkpoint);
	[[nodiscard]] std::vector<SyncRequest> pull();
	[[nodiscard]] std::vector<SyncRequest> submit(
		FilterBlob filter,
		ContentBlob content);
	[[nodiscard]] std::vector<SyncRequest> acceptRead(
		std::uint64_t request,
		RemoteRead result);
	[[nodiscard]] std::vector<SyncRequest> acceptWrite(
		std::uint64_t request,
		RemoteWriteStatus result,
		std::int64_t version = 0);
	void close();
	void discardPendingMutation();

private:
	[[nodiscard]] std::vector<SyncRequest> readPair();
	[[nodiscard]] std::vector<SyncRequest> reconcile();
	[[nodiscard]] std::vector<SyncRequest> nextWrite();
	[[nodiscard]] SyncRequest request(BlobKind kind, SyncOperation operation);
	void block(SyncFailure failure);

	SyncPhase _phase = SyncPhase::Closed;
	SyncFailure _failure = SyncFailure::None;
	SyncPair _remote;
	std::optional<SyncPair> _pending;
	std::optional<PinRegister> _authorizedPin;
	std::optional<RemoteRead> _filterRead;
	std::optional<RemoteRead> _contentRead;
	std::map<std::uint64_t, SyncRequest> _requests;
	std::vector<BlobKind> _writeOrder;
	std::uint64_t _nextRequest = 0;
	int _conflicts = 0;
};

} // namespace Leemen::Sync
