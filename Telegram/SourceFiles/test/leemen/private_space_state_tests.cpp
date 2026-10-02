#include "leemen/private_space_state.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

using Leemen::MessageState;
using Leemen::PinVerificationWindow;
using Leemen::PrivateSpaceSnapshot;
using Leemen::PrivateSpaceState;
using namespace std::chrono_literals;

auto Checks = 0;

void Check(bool condition, std::string_view expression, int line) {
	++Checks;
	if (!condition) {
		std::cerr << "Failed on line " << line << ": " << expression << '\n';
		std::exit(EXIT_FAILURE);
	}
}

#define CHECK(condition) Check(bool(condition), #condition, __LINE__)

void MembershipAndMode() {
	auto state = PrivateSpaceState();
	CHECK(!state.active());
	CHECK(state.allowsPeer(10));
	CHECK(state.setHidden(10, true));
	CHECK(!state.setHidden(10, true));
	CHECK(state.hidden(10));
	CHECK(!state.allowsPeer(10));
	CHECK(!state.allowsChatRow(10));
	CHECK(!state.allowsMessage(10, 100));
	CHECK(state.allowsMessage(20, 100));
	CHECK(state.setActive(true));
	CHECK(!state.setActive(true));
	CHECK(state.hidden(10));
	CHECK(state.allowsPeer(10));
	CHECK(state.allowsChatRow(10));
	CHECK(state.allowsMessage(10, 100));
	CHECK(state.setActive(false));
	CHECK(!state.allowsMessage(10, 100));
	CHECK(state.setHidden(10, false));
	CHECK(!state.setHidden(10, false));
	CHECK(state.allowsPeer(10));
}

void MessageVisibility() {
	auto state = PrivateSpaceState();
	state.setHidden(10, true);
	CHECK(state.markMessage(10, 100, MessageState::Exposed));
	CHECK(state.markMessage(10, 200, MessageState::Pending));
	CHECK(state.markMessage(10, 300, MessageState::Hidden));
	CHECK(!state.markMessage(10, 300, MessageState::Hidden));
	CHECK(state.allowsMessage(10, 100));
	CHECK(state.allowsMessage(10, 200));
	CHECK(!state.allowsMessage(10, 300));
	CHECK(!state.allowsMessage(10, 400));
	CHECK(!state.allowsChatRow(10));
	CHECK(state.allowsChatRow(10, true));
	CHECK(!state.allowsPeer(10));
	CHECK(state.pendingCount(10) == 1);
	CHECK(state.markMessage(10, 100, MessageState::Hidden));
	CHECK(state.markMessage(10, 200, MessageState::Exposed));
	CHECK(state.pendingCount(10) == 0);
	CHECK(!state.allowsMessage(10, 100));
	CHECK(state.allowsMessage(10, 200));
	CHECK(!state.allowsMessage(10, -10));
	CHECK(state.allowsMessage(10, -10, true));
	CHECK(state.allowsMessage(10, 400, true));
	CHECK(!state.allowsMessage(10, 400));
	CHECK(state.markMessage(10, -10, MessageState::Pending));
	CHECK(state.allowsMessage(10, -10));
	CHECK(state.forgetMessage(10, -10));
	CHECK(!state.allowsMessage(10, -10));
	CHECK(state.markMessage(10, 200, MessageState::Hidden));
	CHECK(!state.allowsChatRow(10));
	CHECK(!state.allowsChatRow(10, true));
	CHECK(state.markMessage(10, -10, MessageState::Pending));
	CHECK(state.allowsChatRow(10));
	CHECK(state.markMessage(10, 200, MessageState::Exposed));
	CHECK(!state.allowsChatRow(10));
	CHECK(state.allowsChatRow(10, true));
}

void IsolatedAccountsAndPeers() {
	auto first = PrivateSpaceState();
	auto second = PrivateSpaceState();
	first.setHidden(10, true);
	first.setHidden(20, true);
	first.markMessage(10, 100, MessageState::Pending);
	first.markMessage(20, 200, MessageState::Pending);
	first.markMessage(20, 300, MessageState::Pending);
	first.setSelfPinned(10, 100, true);
	first.setPrivateSearch(30, true);
	CHECK(first.pendingCount(10) == 1);
	CHECK(first.pendingCount(20) == 2);
	CHECK(first.totalPendingCount() == 3);
	CHECK(!first.allowsMessage(20, 100));
	CHECK(second.allowsPeer(10));
	CHECK(second.totalPendingCount() == 0);
	CHECK(!second.selfPinned(10, 100));
	CHECK(!second.privateSearch(30));
	second.setHidden(10, true);
	CHECK(!second.allowsMessage(10, 100));
	first.setActive(true);
	CHECK(!second.active());
	CHECK(!second.allowsPeer(10));
}

void RemovalClearsMetadata() {
	auto state = PrivateSpaceState();
	state.setHidden(10, true);
	state.markMessage(10, 100, MessageState::Exposed);
	state.markMessage(10, 200, MessageState::Pending);
	state.setSelfPinned(10, 100, true);
	state.setPrivateSearch(10, true);
	CHECK(state.setHidden(10, false));
	CHECK(state.snapshot().messages.empty());
	CHECK(state.snapshot().selfPinned.empty());
	CHECK(state.privateSearch(10));
	CHECK(state.pendingCount(10) == 0);
	CHECK(state.setHidden(10, true));
	CHECK(!state.allowsMessage(10, 100));
	CHECK(!state.allowsMessage(10, 200));
	CHECK(!state.selfPinned(10, 100));
}

void MessageConfirmationAndDeletion() {
	auto state = PrivateSpaceState();
	state.setHidden(10, true);
	state.markMessage(10, -10, MessageState::Pending);
	state.markMessage(10, -20, MessageState::Exposed);
	state.setSelfPinned(10, -10, true);
	CHECK(state.replaceMessageId(10, -10, 100));
	CHECK(state.replaceMessageId(10, -20, 200));
	CHECK(!state.allowsMessage(10, -10));
	CHECK(!state.allowsMessage(10, -20));
	CHECK(state.messageState(10, 100) == MessageState::Pending);
	CHECK(state.messageState(10, 200) == MessageState::Exposed);
	CHECK(state.pendingCount(10) == 1);
	CHECK(!state.selfPinned(10, -10));
	CHECK(state.selfPinned(10, 100));
	CHECK(state.forgetMessage(10, 100));
	CHECK(!state.forgetMessage(10, 100));
	CHECK(!state.selfPinned(10, 100));
	CHECK(state.pendingCount(10) == 0);
	CHECK(!state.allowsMessage(10, 100));
	CHECK(state.allowsMessage(10, 200));
	CHECK(state.forgetMessage(10, 200));
	CHECK(state.snapshot().messages.empty());
	CHECK(state.snapshot().selfPinned.empty());
}

void SafeConfirmationCollisions() {
	const auto states = std::array{
		MessageState::Hidden,
		MessageState::Pending,
		MessageState::Exposed,
	};
	for (auto old = 0U; old != states.size(); ++old) {
		for (auto next = 0U; next != states.size(); ++next) {
			auto state = PrivateSpaceState();
			state.setHidden(10, true);
			state.markMessage(10, -10, states[old]);
			state.markMessage(10, 100, states[next]);
			CHECK(state.replaceMessageId(10, -10, 100));
			CHECK(state.messageState(10, 100) == states[std::min(old, next)]);
			CHECK(state.snapshot().messages.at(10).size() == 1);
		}
	}
}

void LocalPinsAndPrivateSearch() {
	auto state = PrivateSpaceState();
	CHECK(!state.setSelfPinned(10, 100, true));
	state.setHidden(10, true);
	CHECK(state.setSelfPinned(10, 100, true));
	CHECK(!state.setSelfPinned(10, 100, true));
	CHECK(state.selfPinned(10, 100));
	CHECK(!state.allowsMessage(10, 100));
	CHECK(!state.allowsChatRow(10));
	CHECK(state.setSelfPinned(10, 100, false));
	CHECK(!state.setSelfPinned(10, 100, false));
	CHECK(state.snapshot().selfPinned.empty());
	CHECK(state.setPrivateSearch(20, true));
	CHECK(!state.setPrivateSearch(20, true));
	CHECK(!state.allowsRecentSearch(20));
	CHECK(state.allowsPeer(20));
	CHECK(state.allowsRecentSearch(30));
	state.setActive(true);
	CHECK(state.allowsRecentSearch(20));
	CHECK(state.allowsRecentSearch(10));
	state.setActive(false);
	CHECK(state.setPrivateSearch(20, false));
	CHECK(state.allowsRecentSearch(20));
	CHECK(!state.allowsRecentSearch(10));
}

void RestorationLocks() {
	auto original = PrivateSpaceState();
	original.setHidden(10, true);
	original.markMessage(10, 100, MessageState::Pending);
	original.markMessage(10, 200, MessageState::Exposed);
	original.setSelfPinned(10, 300, true);
	original.setPrivateSearch(20, true);
	original.setActive(true);
	auto restored = PrivateSpaceState();
	CHECK(restored.restore(original.snapshot()));
	CHECK(!restored.active());
	CHECK(!restored.allowsPeer(10));
	CHECK(restored.allowsMessage(10, 100));
	CHECK(restored.allowsMessage(10, 200));
	CHECK(!restored.allowsMessage(10, 300));
	CHECK(restored.selfPinned(10, 300));
	CHECK(!restored.allowsRecentSearch(20));
	restored.setActive(true);
	CHECK(restored.restore(restored.snapshot()));
	CHECK(!restored.active());
	CHECK(original.active());
	CHECK(restored.restore(PrivateSpaceSnapshot()));
	CHECK(!restored.hidden(10));
	CHECK(!restored.selfPinned(10, 300));
	CHECK(!restored.privateSearch(20));
}

void InvalidInputIsRejected() {
	auto state = PrivateSpaceState();
	CHECK(!state.setHidden(0, true));
	CHECK(!state.setPrivateSearch(0, true));
	CHECK(!state.allowsPeer(0));
	CHECK(!state.allowsChatRow(0));
	CHECK(!state.allowsMessage(0, 1, true));
	CHECK(!state.allowsMessage(1, 0, true));
	CHECK(!state.markMessage(10, 100, MessageState::Exposed));
	state.setHidden(10, true);
	CHECK(!state.markMessage(10, 0, MessageState::Pending));
	CHECK(!state.markMessage(10, 100, MessageState(255)));
	CHECK(!state.setSelfPinned(10, 0, true));
	CHECK(!state.replaceMessageId(10, 0, 1));
	CHECK(!state.replaceMessageId(10, 1, 0));
	CHECK(!state.replaceMessageId(10, 1, 1));
	CHECK(state.snapshot().messages.empty());
	CHECK(state.setHidden(std::numeric_limits<std::uint64_t>::max(), true));
	CHECK(!state.allowsPeer(std::numeric_limits<std::uint64_t>::max()));
	state.setActive(true);
	CHECK(!state.allowsPeer(0));
	CHECK(!state.allowsMessage(10, 0));
	const auto invalidSnapshots = std::array{
		PrivateSpaceSnapshot{ .hiddenPeers = { 0 } },
		PrivateSpaceSnapshot{
			.messages = { { 10, { { 1, MessageState::Exposed } } } },
		},
		PrivateSpaceSnapshot{
			.hiddenPeers = { 10 },
			.messages = { { 10, {} } },
		},
		PrivateSpaceSnapshot{
			.hiddenPeers = { 10 },
			.messages = { { 10, { { 0, MessageState::Exposed } } } },
		},
		PrivateSpaceSnapshot{
			.hiddenPeers = { 10 },
			.messages = { { 10, { { 1, MessageState(255) } } } },
		},
		PrivateSpaceSnapshot{ .selfPinned = { { 10, { 1 } } } },
		PrivateSpaceSnapshot{
			.hiddenPeers = { 10 },
			.selfPinned = { { 10, { 0 } } },
		},
		PrivateSpaceSnapshot{ .privateSearchPeers = { 0 } },
	};
	for (const auto &invalid : invalidSnapshots) {
		state.setActive(true);
		CHECK(!state.restore(invalid));
		CHECK(!state.active());
		CHECK(state.hidden(10));
		CHECK(!state.allowsPeer(10));
		CHECK(state.snapshot().messages.empty());
		CHECK(state.snapshot().selfPinned.empty());
	}
}

void VerificationGraceIsMonotonicAndLocal() {
	static_assert(PinVerificationWindow::Clock::is_steady);
	const auto start = PinVerificationWindow::Time();
	auto grace = PinVerificationWindow(5min);
	CHECK(!grace.skippable(start));
	grace.recordVerified(start);
	CHECK(grace.skippable(start));
	CHECK(grace.skippable(start + 5min - 1ms));
	CHECK(!grace.skippable(start + 5min));
	CHECK(!grace.skippable(start - 1ms));
	CHECK(!PinVerificationWindow(5min).skippable(start + 1min));
	grace.setTimeout(5min);
	CHECK(grace.skippable(start + 1min));
	grace.setTimeout(10min);
	CHECK(!grace.skippable(start + 1min));
	grace.recordVerified(start + 1min);
	CHECK(grace.skippable(start + 2min));
	grace.clear();
	CHECK(!grace.skippable(start + 2min));
	grace.setTimeout(0min);
	grace.recordVerified(start);
	CHECK(!grace.skippable(start));
	grace.setTimeout(-5min);
	grace.recordVerified(start);
	CHECK(!grace.skippable(start));
	grace.setTimeout(std::chrono::minutes::max());
	grace.recordVerified(start);
	CHECK(grace.skippable(start + 1min));
}

} // namespace

int main() {
	MembershipAndMode();
	MessageVisibility();
	IsolatedAccountsAndPeers();
	RemovalClearsMetadata();
	MessageConfirmationAndDeletion();
	SafeConfirmationCollisions();
	LocalPinsAndPrivateSearch();
	RestorationLocks();
	InvalidInputIsRejected();
	VerificationGraceIsMonotonicAndLocal();
	std::cout << "Leemen private-space core: " << Checks << " checks passed.\n";
}
