#include "leemen/security_policy.h"

#include <cstdlib>
#include <iostream>
#include <limits>

namespace {

using namespace Leemen::Security;
using Leemen::Sync::Backend::MeReply;
constexpr auto kNow = std::int64_t(1'800'000'000'000);
auto Checks = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

MeReply Reply(std::optional<std::int64_t> expiry) {
	auto result = MeReply();
	result.serverNowMs = kNow;
	result.entitlements.push_back({ "premium", "manual", expiry, kNow - 1000 });
	return result;
}

void ClockTests() {
	auto clock = PremiumClock();
	Check(clock.snapshot(100).access == PremiumAccess::Unknown, "unverified is unknown");
	auto missing = Reply(kNow + 1000);
	missing.serverNowMs.reset();
	Check(!clock.apply(missing, 100), "missing server time rejected");
	Check(clock.snapshot(100).access == PremiumAccess::Unknown, "missing time grants nothing");
	auto good = Reply(kNow + 1000);
	Check(clock.apply(good, 100), "trusted snapshot accepted");
	auto status = clock.snapshot(100);
	Check(status.access == PremiumAccess::Active, "premium active");
	Check(status.displayUntilMs == kNow + 1000, "absolute time only display");
	Check(status.deadlineMonotonicMs == 1100, "deadline anchored in monotonic domain");
	Check(!clock.apply(missing, 200), "invalid reply does not extend premium");
	Check(clock.snapshot(1099).access == PremiumAccess::Active, "before deadline active");
	Check(clock.snapshot(1100).access == PremiumAccess::Inactive, "expiry boundary exclusive");
	Check(clock.snapshot(1500).access == PremiumAccess::Inactive, "expiry remains inactive");
	Check(clock.snapshot(1000).access == PremiumAccess::Unknown, "clock rollback loses trust");
	Check(clock.snapshot(1600).access == PremiumAccess::Unknown, "rollback does not recover stale deadline");
	Check(clock.apply(good, 1600), "new trusted response restores after rollback");
	Check(clock.snapshot(1600).deadlineMonotonicMs == 2600, "restored time reanchored");
	Check(clock.snapshot(-1).access == PremiumAccess::Unknown, "negative clock rejects");
	Check(!clock.apply(good, -1), "negative apply rejects");
	clock.clear();
	Check(clock.snapshot(0).access == PremiumAccess::Unknown, "new process never trusts old snapshot");
	Check(clock.apply(Reply(kNow), 0), "already expired response valid");
	Check(clock.snapshot(0).access == PremiumAccess::Inactive, "expired response has no access");
	Check(!clock.snapshot(0).deadlineMonotonicMs, "no active deadline for expired response");
	Check(clock.apply(Reply(std::nullopt), 0), "perpetual grants accepted");
	status = clock.snapshot(0);
	Check(status.displayUntilMs == kPerpetualPremiumUntilMs, "Android year 2100 sentinel");
	Check(status.deadlineMonotonicMs == kPerpetualPremiumUntilMs - kNow, "perpetual also anchored");
	Check(clock.snapshot(*status.deadlineMonotonicMs).access == PremiumAccess::Inactive, "Android perpetual sentinel exact expiry");
	clock.clear();
	auto mixed = Reply(kNow + 1000);
	mixed.entitlements.push_back({ "premium", "play", kNow + 3000, kNow });
	mixed.entitlements.push_back({ "unrelated", "manual", std::nullopt, kNow });
	mixed.entitlements.push_back({ "premium", "future-source", kNow + 2000, kNow });
	Check(clock.apply(mixed, 400), "multiple premium sources accepted");
	Check(clock.snapshot(400).deadlineMonotonicMs == 3400, "latest expiry across sources wins");
	mixed.entitlements.clear();
	Check(clock.apply(mixed, 400), "empty authoritative entitlements valid");
	Check(clock.snapshot(400).access == PremiumAccess::Inactive, "valid revocation applies");
	Check(clock.apply(good, 400), "restore before malformed snapshot");
	const auto previous = clock.snapshot(400);
	for (const auto invalid : { -1LL, 0LL }) {
		auto bad = Reply(invalid);
		Check(!clock.apply(bad, 400), "invalid expiry rejected");
		Check(clock.snapshot(400) == previous, "invalid expiry preserves old bounded trust");
		bad = good;
		bad.serverNowMs = invalid;
		Check(!clock.apply(bad, 400), "invalid server time rejected");
		Check(clock.snapshot(400) == previous, "invalid time preserves old bounded trust");
	}
	clock.clear();
	const auto max = std::numeric_limits<std::int64_t>::max();
	Check(clock.apply(Reply(max), max - 100), "large valid expiry bounded");
	Check(clock.snapshot(max - 100).deadlineMonotonicMs == max, "deadline saturates without overflow");
	Check(clock.snapshot(max).access == PremiumAccess::Inactive, "saturated deadline expires");
}

void LimitsTests() {
	for (const auto premium : { false, true }) {
		for (const auto chats : { std::size_t(0), std::size_t(1), std::size_t(2), std::numeric_limits<std::size_t>::max() }) {
			for (const auto accounts : { std::size_t(0), std::size_t(1), std::numeric_limits<std::size_t>::max() }) {
				const auto limits = EvaluateHiddenLimits(premium, chats, accounts);
				Check(limits.chatsOverLimit == (!premium && chats > 1), "chat limit");
				Check(limits.accountsOverLimit == (!premium && accounts > 0), "account limit");
				Check((limits.entry == EntryDecision::RenewOrReveal) == (!premium && (chats > 1 || accounts > 0)), "over-limit gates entry without exposing anything");
				Check(limits.freeChatSlots == (premium ? std::numeric_limits<std::size_t>::max() : chats == 0 ? 1 : 0), "free chat slots bounded");
			}
		}
	}
	Check(CanAddChats(false, 0, 1), "first hidden chat free");
	Check(!CanAddChats(false, 1, 1), "second hidden chat requires premium");
	Check(!CanAddChats(false, 0, 2), "batch cannot bypass free limit");
	Check(!CanAddChats(false, std::numeric_limits<std::size_t>::max(), 1), "count overflow cannot bypass limit");
	Check(!CanAddChats(false, 1, std::numeric_limits<std::size_t>::max()), "delta overflow cannot bypass limit");
	Check(CanAddChats(true, 5, 6), "premium unlimited chats");
	Check(CanAddChats(false, 5, 0), "idempotent update remains possible after expiry");
	for (const auto premium : { false, true }) {
		Check(!CanHideAccount(premium, true, false, false), "cannot hide self");
		Check(!CanHideAccount(premium, true, false, true), "self still invalid if marked hidden");
		Check(!CanHideAccount(premium, false, true, false), "cannot hide owner account");
		Check(CanHideAccount(premium, false, false, true), "existing hidden account preserved after expiry");
		Check(CanHideAccount(premium, false, false, false) == premium, "new hidden accounts premium only");
	}
	for (const auto requested : { false, true }) {
		for (const auto configured : { false, true }) {
			for (const auto tested : { false, true }) {
				Check(IsEntryButtonVisible(requested, configured, tested) == (requested || !(configured && tested)), "entry always recoverable until shortcut tested");
			}
		}
	}
}

} // namespace

int main() {
	ClockTests();
	LimitsTests();
	std::cout << "Security policy checks passed: " << Checks << '\n';
}
