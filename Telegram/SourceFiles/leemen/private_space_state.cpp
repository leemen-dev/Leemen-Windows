#include "leemen/private_space_state.h"

#include <algorithm>

namespace Leemen {
namespace {

constexpr auto kMaximumSnapshotEntries = std::size_t(1'000'000);

[[nodiscard]] bool ValidMessageState(MessageState state) {
	switch (state) {
	case MessageState::Hidden:
	case MessageState::Pending:
	case MessageState::Exposed:
		return true;
	}
	return false;
}

[[nodiscard]] int PrivacyRank(MessageState state) {
	switch (state) {
	case MessageState::Hidden: return 2;
	case MessageState::Pending: return 1;
	case MessageState::Exposed: return 0;
	}
	return 2;
}

[[nodiscard]] bool ValidSnapshot(const PrivateSpaceSnapshot &snapshot) {
	if (snapshot.hiddenPeers.contains(0)
		|| snapshot.privateSearchPeers.contains(0)
		|| snapshot.hiddenPeers.size() > kMaximumSnapshotEntries
		|| snapshot.privateSearchPeers.size() > kMaximumSnapshotEntries) {
		return false;
	}
	auto remaining = kMaximumSnapshotEntries;
	for (const auto &[peer, messages] : snapshot.messages) {
		if (!snapshot.hiddenPeers.contains(peer)
			|| messages.empty()
			|| messages.size() > remaining) {
			return false;
		}
		remaining -= messages.size();
		for (const auto &[message, state] : messages) {
			if (!message || !ValidMessageState(state)) {
				return false;
			}
		}
	}
	for (const auto &[peer, messages] : snapshot.selfPinned) {
		if (!snapshot.hiddenPeers.contains(peer)
			|| messages.empty()
			|| messages.contains(0)
			|| messages.size() > remaining) {
			return false;
		}
		remaining -= messages.size();
	}
	return true;
}

} // namespace

bool PrivateSpaceState::active() const {
	return _active;
}

bool PrivateSpaceState::setActive(bool active) {
	if (_active == active) {
		return false;
	}
	_active = active;
	return true;
}

bool PrivateSpaceState::hidden(std::uint64_t peer) const {
	return _snapshot.hiddenPeers.contains(peer);
}

bool PrivateSpaceState::setHidden(std::uint64_t peer, bool hidden) {
	if (!peer) {
		return false;
	}
	if (hidden) {
		return _snapshot.hiddenPeers.emplace(peer).second;
	}
	if (!_snapshot.hiddenPeers.erase(peer)) {
		return false;
	}
	_snapshot.messages.erase(peer);
	_snapshot.selfPinned.erase(peer);
	return true;
}

bool PrivateSpaceState::allowsPeer(std::uint64_t peer) const {
	return peer && (_active || !hidden(peer));
}

bool PrivateSpaceState::allowsChatRow(
		std::uint64_t peer,
		bool safePreviewResolved) const {
	if (allowsPeer(peer)) {
		return true;
	}
	const auto i = _snapshot.messages.find(peer);
	if (i == end(_snapshot.messages)) {
		return false;
	}
	auto safe = false;
	for (const auto &[message, state] : i->second) {
		if (state != MessageState::Hidden) {
			if (message > 0) {
				return safePreviewResolved;
			}
			safe = true;
		}
	}
	return safe;
}

bool PrivateSpaceState::allowsMessage(
		std::uint64_t peer,
		std::int64_t message,
		bool outgoingInFlight) const {
	return peer
		&& message
		&& (allowsPeer(peer)
			|| outgoingInFlight
			|| messageState(peer, message) != MessageState::Hidden);
}

MessageState PrivateSpaceState::messageState(
		std::uint64_t peer,
		std::int64_t message) const {
	const auto i = _snapshot.messages.find(peer);
	if (i != end(_snapshot.messages)) {
		const auto j = i->second.find(message);
		if (j != end(i->second)) {
			return j->second;
		}
	}
	return MessageState::Hidden;
}

bool PrivateSpaceState::markMessage(
		std::uint64_t peer,
		std::int64_t message,
		MessageState state) {
	if (!hidden(peer) || !message || !ValidMessageState(state)) {
		return false;
	}
	auto &messages = _snapshot.messages[peer];
	const auto i = messages.find(message);
	if (i != end(messages) && i->second == state) {
		return false;
	}
	messages[message] = state;
	return true;
}

bool PrivateSpaceState::replaceMessageId(
		std::uint64_t peer,
		std::int64_t oldMessage,
		std::int64_t newMessage) {
	if (!hidden(peer) || !oldMessage || !newMessage || oldMessage == newMessage) {
		return false;
	}
	auto changed = false;
	const auto messages = _snapshot.messages.find(peer);
	if (messages != end(_snapshot.messages)) {
		auto &entries = messages->second;
		const auto old = entries.find(oldMessage);
		if (old != end(entries)) {
			const auto next = entries.find(newMessage);
			const auto state = old->second;
			if (next == end(entries)
				|| PrivacyRank(state) > PrivacyRank(next->second)) {
				entries[newMessage] = state;
			}
			entries.erase(old);
			changed = true;
		}
	}
	const auto pins = _snapshot.selfPinned.find(peer);
	if (pins != end(_snapshot.selfPinned) && pins->second.erase(oldMessage)) {
		pins->second.emplace(newMessage);
		changed = true;
	}
	return changed;
}

bool PrivateSpaceState::forgetMessage(
		std::uint64_t peer,
		std::int64_t message) {
	auto changed = false;
	const auto messages = _snapshot.messages.find(peer);
	if (messages != end(_snapshot.messages)) {
		changed = messages->second.erase(message) != 0;
		if (messages->second.empty()) {
			_snapshot.messages.erase(messages);
		}
	}
	const auto pins = _snapshot.selfPinned.find(peer);
	if (pins != end(_snapshot.selfPinned)) {
		changed = (pins->second.erase(message) != 0) || changed;
		if (pins->second.empty()) {
			_snapshot.selfPinned.erase(pins);
		}
	}
	return changed;
}

std::size_t PrivateSpaceState::pendingCount(std::uint64_t peer) const {
	const auto i = _snapshot.messages.find(peer);
	return (i == end(_snapshot.messages))
		? 0
		: std::count_if(begin(i->second), end(i->second), [](const auto &entry) {
			return entry.second == MessageState::Pending;
		});
}

std::size_t PrivateSpaceState::totalPendingCount() const {
	auto result = std::size_t(0);
	for (const auto &[peer, messages] : _snapshot.messages) {
		result += pendingCount(peer);
	}
	return result;
}

bool PrivateSpaceState::setSelfPinned(
		std::uint64_t peer,
		std::int64_t message,
		bool pinned) {
	if (!hidden(peer) || !message) {
		return false;
	}
	if (pinned) {
		return _snapshot.selfPinned[peer].emplace(message).second;
	}
	const auto i = _snapshot.selfPinned.find(peer);
	if (i == end(_snapshot.selfPinned) || !i->second.erase(message)) {
		return false;
	}
	if (i->second.empty()) {
		_snapshot.selfPinned.erase(i);
	}
	return true;
}

bool PrivateSpaceState::selfPinned(
		std::uint64_t peer,
		std::int64_t message) const {
	const auto i = _snapshot.selfPinned.find(peer);
	return i != end(_snapshot.selfPinned) && i->second.contains(message);
}

bool PrivateSpaceState::setPrivateSearch(
		std::uint64_t peer,
		bool privateSearch) {
	if (!peer) {
		return false;
	}
	return privateSearch
		? _snapshot.privateSearchPeers.emplace(peer).second
		: _snapshot.privateSearchPeers.erase(peer) != 0;
}

bool PrivateSpaceState::privateSearch(std::uint64_t peer) const {
	return _snapshot.privateSearchPeers.contains(peer);
}

bool PrivateSpaceState::allowsRecentSearch(std::uint64_t peer) const {
	return allowsPeer(peer) && (_active || !privateSearch(peer));
}

const PrivateSpaceSnapshot &PrivateSpaceState::snapshot() const {
	return _snapshot;
}

bool PrivateSpaceState::restore(const PrivateSpaceSnapshot &snapshot) {
	_active = false;
	if (!ValidSnapshot(snapshot)) {
		return false;
	}
	_snapshot = snapshot;
	return true;
}

PinVerificationWindow::PinVerificationWindow(std::chrono::minutes timeout) {
	setTimeout(timeout);
}

void PinVerificationWindow::setTimeout(std::chrono::minutes timeout) {
	timeout = std::max(timeout, std::chrono::minutes::zero());
	if (_timeout != timeout) {
		_timeout = timeout;
		clear();
	}
}

void PinVerificationWindow::recordVerified(Time now) {
	_verified = now;
}

void PinVerificationWindow::clear() {
	_verified.reset();
}

bool PinVerificationWindow::skippable(Time now) const {
	return _timeout > std::chrono::minutes::zero()
		&& _verified
		&& now >= *_verified
		&& std::chrono::duration_cast<std::chrono::minutes>(now - *_verified)
			< _timeout;
}

} // namespace Leemen
