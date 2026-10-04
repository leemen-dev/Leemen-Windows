#include "leemen/security_policy.h"

#include <algorithm>
#include <limits>

namespace Leemen::Security {

bool PremiumClock::apply(
		const Sync::Backend::MeReply &reply,
		std::int64_t monotonicMs) {
	if (!observe(monotonicMs)
		|| !reply.serverNowMs
		|| *reply.serverNowMs <= 0) {
		return false;
	}
	auto until = std::int64_t(0);
	for (const auto &entitlement : reply.entitlements) {
		if (entitlement.kind != "premium") {
			continue;
		}
		const auto expiry = entitlement.expiresAtMs.value_or(kPerpetualPremiumUntilMs);
		if (expiry <= 0) {
			return false;
		}
		if (expiry > *reply.serverNowMs) {
			until = std::max(until, expiry);
		}
	}
	_snapshot.displayUntilMs = until;
	if (until == 0) {
		_snapshot.access = PremiumAccess::Inactive;
		_snapshot.deadlineMonotonicMs.reset();
	} else {
		const auto remaining = until - *reply.serverNowMs;
		const auto maximum = std::numeric_limits<std::int64_t>::max();
		_snapshot.access = PremiumAccess::Active;
		_snapshot.deadlineMonotonicMs = (remaining > maximum - monotonicMs)
			? maximum
			: monotonicMs + remaining;
	}
	return true;
}

PremiumSnapshot PremiumClock::snapshot(std::int64_t monotonicMs) {
	if (observe(monotonicMs)
		&& _snapshot.access == PremiumAccess::Active
		&& monotonicMs >= *_snapshot.deadlineMonotonicMs) {
		_snapshot.access = PremiumAccess::Inactive;
	}
	return _snapshot;
}

void PremiumClock::clear() {
	_snapshot = {};
	_lastObservedMs.reset();
}

bool PremiumClock::observe(std::int64_t monotonicMs) {
	if (monotonicMs < 0 || (_lastObservedMs && monotonicMs < *_lastObservedMs)) {
		_snapshot = {};
		return false;
	}
	_lastObservedMs = monotonicMs;
	return true;
}

HiddenLimits EvaluateHiddenLimits(
		bool premiumActive,
		std::size_t hiddenChats,
		std::size_t hiddenAccounts) {
	const auto chatsOver = !premiumActive && hiddenChats > kFreeHiddenChats;
	const auto accountsOver = !premiumActive && hiddenAccounts > kFreeHiddenAccounts;
	return {
		chatsOver,
		accountsOver,
		(chatsOver || accountsOver) ? EntryDecision::RenewOrReveal : EntryDecision::Allowed,
		premiumActive ? std::numeric_limits<std::size_t>::max()
			: (hiddenChats < kFreeHiddenChats) ? kFreeHiddenChats - hiddenChats : 0,
	};
}

bool CanAddChats(
		bool premiumActive,
		std::size_t hiddenChats,
		std::size_t additionalChats) {
	if (premiumActive || additionalChats == 0) {
		return true;
	}
	return hiddenChats < kFreeHiddenChats
		&& additionalChats <= kFreeHiddenChats - hiddenChats;
}

bool CanHideAccount(
		bool premiumActive,
		bool isSelf,
		bool targetOwnsHiddenAccounts,
		bool alreadyHidden) {
	return !isSelf && (alreadyHidden || (premiumActive && !targetOwnsHiddenAccounts));
}

bool IsEntryButtonVisible(
		bool requestedVisible,
		bool shortcutConfigured,
		bool shortcutTested) {
	return requestedVisible || !shortcutConfigured || !shortcutTested;
}

} // namespace Leemen::Security
