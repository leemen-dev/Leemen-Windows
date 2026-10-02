#include "leemen/sync_coordinator.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace Leemen::Sync {
namespace {

constexpr auto kMaximumVersion = std::int64_t(9007199254740991LL);
constexpr auto kMaximumConflicts = 3;

bool ValidRead(const RemoteRead &read) {
	return (read.status == RemoteReadStatus::Absent
			&& !read.version
			&& read.plaintext.empty())
		|| (read.status == RemoteReadStatus::Present
			&& read.version > 0
			&& read.version <= kMaximumVersion
			&& !read.plaintext.empty());
}

std::optional<std::string_view> Plaintext(const RemoteRead &read) {
	return (read.status == RemoteReadStatus::Absent)
		? std::nullopt
		: std::make_optional<std::string_view>(read.plaintext);
}

bool RemovesMembership(const FilterBlob &before, const FilterBlob &after) {
	for (const auto &[id, value] : before.hiddenChatIds) {
		const auto i = after.hiddenChatIds.find(id);
		if (ProtectsMembership(value)
			&& i != after.hiddenChatIds.end()
			&& !ProtectsMembership(i->second)) {
			return true;
		}
	}

	return false;
}

} // namespace

SyncPhase SyncCoordinator::phase() const {
	return _phase;
}

SyncFailure SyncCoordinator::failure() const {
	return _failure;
}

const SyncPair *SyncCoordinator::projection() const {
	return (_phase == SyncPhase::Ready) ? &_remote : nullptr;
}

const SyncPair *SyncCoordinator::pendingMutation() const {
	return _pending ? &*_pending : nullptr;
}

SyncCheckpoint SyncCoordinator::checkpoint() const {
	return { _pending, _authorizedPin };
}

bool SyncCoordinator::restoreCheckpoint(SyncCheckpoint checkpoint) {
	close();
	if (!checkpoint.pending) {
		return !checkpoint.authorizedPin;
	}
	const auto &pair = *checkpoint.pending;
	auto expectedPin = ContentBlob();
	expectedPin.pin = checkpoint.authorizedPin;
	if (pair.filterVersion < 0 || pair.filterVersion > kMaximumVersion
		|| pair.contentVersion < 0 || pair.contentVersion > kMaximumVersion
		|| !EncodeFilterBlob(pair.filter)
		|| !EncodeContentBlob(pair.content)
		|| !EncodeContentBlob(expectedPin)) {
		block(SyncFailure::InvalidData);
		return false;
	}
	_pending = std::move(checkpoint.pending);
	_authorizedPin = std::move(checkpoint.authorizedPin);
	return true;
}

std::vector<SyncRequest> SyncCoordinator::pull() {
	if (_phase == SyncPhase::Reading || _phase == SyncPhase::Writing) {
		return {};
	} else if (_failure == SyncFailure::AuthorizationChanged && _pending) {
		return {};
	}
	_conflicts = 0;
	return readPair();
}

std::vector<SyncRequest> SyncCoordinator::submit(
		FilterBlob filter,
		ContentBlob content) {
	if (_phase != SyncPhase::Ready || _pending) {
		return {};
	}
	RecomputeOffModeVisible(filter, content);
	if (!EncodeFilterBlob(filter) || !EncodeContentBlob(content)) {
		return {};
	}
	_authorizedPin = _remote.content.pin;
	_pending = SyncPair{
		std::move(filter),
		std::move(content),
		_remote.filterVersion,
		_remote.contentVersion,
	};
	_conflicts = 0;
	return readPair();
}

std::vector<SyncRequest> SyncCoordinator::readPair() {
	_requests.clear();
	_filterRead.reset();
	_contentRead.reset();
	_writeOrder.clear();
	_phase = SyncPhase::Reading;
	_failure = SyncFailure::None;
	return {
		request(BlobKind::Filter, SyncOperation::Read),
		request(BlobKind::Content, SyncOperation::Read),
	};
}

SyncRequest SyncCoordinator::request(
		BlobKind kind,
		SyncOperation operation) {
	auto result = SyncRequest();
	result.id = ++_nextRequest;
	result.kind = kind;
	result.operation = operation;
	if (operation == SyncOperation::Write) {
		result.previousVersion = (kind == BlobKind::Filter)
			? _remote.filterVersion
			: _remote.contentVersion;
		result.plaintext = (kind == BlobKind::Filter)
			? EncodeFilterBlob(_pending->filter)
			: EncodeContentBlob(_pending->content);
	}
	_requests.emplace(result.id, result);
	return result;
}

std::vector<SyncRequest> SyncCoordinator::acceptRead(
		std::uint64_t id,
		RemoteRead result) {
	const auto i = _requests.find(id);
	if (_phase != SyncPhase::Reading
		|| i == _requests.end()
		|| i->second.operation != SyncOperation::Read) {
		return {};
	}
	const auto kind = i->second.kind;
	_requests.erase(i);
	if (result.status == RemoteReadStatus::Failed) {
		block(SyncFailure::Transport);
		return {};
	} else if (!ValidRead(result)) {
		block(SyncFailure::InvalidData);
		return {};
	}
	((kind == BlobKind::Filter) ? _filterRead : _contentRead) = std::move(result);
	return (_filterRead && _contentRead) ? reconcile() : std::vector<SyncRequest>();
}

std::vector<SyncRequest> SyncCoordinator::reconcile() {
	auto filter = ReadFilterBlob(Plaintext(*_filterRead));
	auto content = ReadContentBlob(Plaintext(*_contentRead));
	if (filter.status == BlobReadStatus::Absent) {
		filter.blob = FilterBlob();
	}
	if (content.status == BlobReadStatus::Absent) {
		content.blob = ContentBlob();
	}
	if (!filter.blob || !content.blob) {
		block((filter.status == BlobReadStatus::UnsupportedSchema
			|| content.status == BlobReadStatus::UnsupportedSchema)
			? SyncFailure::UnsupportedSchema
			: SyncFailure::InvalidData);
		return {};
	}
	if (_pending && content.blob->pin != _authorizedPin) {
		block(SyncFailure::AuthorizationChanged);
		return {};
	}
	_remote = SyncPair{
		*filter.blob,
		*content.blob,
		_filterRead->version,
		_contentRead->version,
	};
	_filterRead.reset();
	_contentRead.reset();
	if (!_pending) {
		RecomputeOffModeVisible(_remote.filter, _remote.content);
		_phase = SyncPhase::Ready;
		return {};
	}
	_pending->filter = MergeFilter(_remote.filter, _pending->filter);
	_pending->content = MergeContent(_remote.content, _pending->content);
	RecomputeOffModeVisible(_pending->filter, _pending->content);
	if (!EncodeFilterBlob(_pending->filter)
		|| !EncodeContentBlob(_pending->content)) {
		block(SyncFailure::InvalidData);
		return {};
	}
	const auto filterChanged = _remote.filter != _pending->filter;
	const auto contentChanged = _remote.content != _pending->content;
	const auto removal = RemovesMembership(_remote.filter, _pending->filter);
	if (filterChanged && removal) {
		_writeOrder.push_back(BlobKind::Filter);
	}
	if (contentChanged) {
		_writeOrder.push_back(BlobKind::Content);
	}
	if (filterChanged && !removal) {
		_writeOrder.push_back(BlobKind::Filter);
	}
	return nextWrite();
}

std::vector<SyncRequest> SyncCoordinator::nextWrite() {
	if (_writeOrder.empty()) {
		_pending.reset();
		_authorizedPin.reset();
		_phase = SyncPhase::Ready;
		return {};
	}
	const auto kind = _writeOrder.front();
	const auto version = (kind == BlobKind::Filter)
		? _remote.filterVersion
		: _remote.contentVersion;
	if (version >= kMaximumVersion) {
		block(SyncFailure::InvalidData);
		return {};
	}
	_writeOrder.erase(_writeOrder.begin());
	_phase = SyncPhase::Writing;
	return { request(kind, SyncOperation::Write) };
}

std::vector<SyncRequest> SyncCoordinator::acceptWrite(
		std::uint64_t id,
		RemoteWriteStatus result,
		std::int64_t version) {
	const auto i = _requests.find(id);
	if (_phase != SyncPhase::Writing
		|| i == _requests.end()
		|| i->second.operation != SyncOperation::Write) {
		return {};
	}
	const auto sent = i->second;
	_requests.erase(i);
	if (result == RemoteWriteStatus::Conflict) {
		if (++_conflicts > kMaximumConflicts) {
			block(SyncFailure::ConflictLimit);
			return {};
		}
		return readPair();
	} else if (result != RemoteWriteStatus::Accepted) {
		block(SyncFailure::Transport);
		return {};
	} else if (version != sent.previousVersion + 1) {
		block(SyncFailure::InvalidData);
		return {};
	}
	if (sent.kind == BlobKind::Filter) {
		_remote.filter = _pending->filter;
		_remote.filterVersion = version;
	} else {
		_remote.content = _pending->content;
		_remote.contentVersion = version;
		_authorizedPin = _remote.content.pin;
	}
	return nextWrite();
}

void SyncCoordinator::block(SyncFailure failure) {
	_phase = SyncPhase::Blocked;
	_failure = failure;
	_requests.clear();
	_filterRead.reset();
	_contentRead.reset();
	_writeOrder.clear();
}

void SyncCoordinator::close() {
	block(SyncFailure::None);
	_phase = SyncPhase::Closed;
	_remote = SyncPair();
	_pending.reset();
	_authorizedPin.reset();
}

void SyncCoordinator::discardPendingMutation() {
	_pending.reset();
	_authorizedPin.reset();
	block(SyncFailure::None);
}

} // namespace Leemen::Sync
