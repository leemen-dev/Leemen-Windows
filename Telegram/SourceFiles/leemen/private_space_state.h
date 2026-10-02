#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>

namespace Leemen {

enum class MessageState {
	Hidden,
	Pending,
	Exposed,
};

struct PrivateSpaceSnapshot {
	std::set<std::uint64_t> hiddenPeers;
	std::map<std::uint64_t, std::map<std::int64_t, MessageState>> messages;
	std::map<std::uint64_t, std::set<std::int64_t>> selfPinned;
	std::set<std::uint64_t> privateSearchPeers;
};

class PrivateSpaceState final {
public:
	[[nodiscard]] bool active() const;
	bool setActive(bool active);
	[[nodiscard]] bool hidden(std::uint64_t peer) const;
	bool setHidden(std::uint64_t peer, bool hidden);
	[[nodiscard]] bool allowsPeer(std::uint64_t peer) const;
	[[nodiscard]] bool allowsChatRow(
		std::uint64_t peer,
		bool safePreviewResolved = false) const;
	[[nodiscard]] bool allowsMessage(
		std::uint64_t peer,
		std::int64_t message,
		bool outgoingInFlight = false) const;
	[[nodiscard]] MessageState messageState(
		std::uint64_t peer,
		std::int64_t message) const;
	bool markMessage(
		std::uint64_t peer,
		std::int64_t message,
		MessageState state);
	bool replaceMessageId(
		std::uint64_t peer,
		std::int64_t oldMessage,
		std::int64_t newMessage);
	bool forgetMessage(std::uint64_t peer, std::int64_t message);
	[[nodiscard]] std::size_t pendingCount(std::uint64_t peer) const;
	[[nodiscard]] std::size_t totalPendingCount() const;
	bool setSelfPinned(
		std::uint64_t peer,
		std::int64_t message,
		bool pinned);
	[[nodiscard]] bool selfPinned(
		std::uint64_t peer,
		std::int64_t message) const;
	bool setPrivateSearch(std::uint64_t peer, bool privateSearch);
	[[nodiscard]] bool privateSearch(std::uint64_t peer) const;
	[[nodiscard]] bool allowsRecentSearch(std::uint64_t peer) const;
	[[nodiscard]] const PrivateSpaceSnapshot &snapshot() const;
	bool restore(const PrivateSpaceSnapshot &snapshot);

private:
	PrivateSpaceSnapshot _snapshot;
	bool _active = false;

};

class PinVerificationWindow final {
public:
	using Clock = std::chrono::steady_clock;
	using Time = Clock::time_point;

	explicit PinVerificationWindow(std::chrono::minutes timeout = {});
	void setTimeout(std::chrono::minutes timeout);
	void recordVerified(Time now = Clock::now());
	void clear();
	[[nodiscard]] bool skippable(Time now = Clock::now()) const;

private:
	std::chrono::minutes _timeout = {};
	std::optional<Time> _verified;

};

} // namespace Leemen
