#pragma once

#include "leemen/sync_backend.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace Leemen::Security {

inline constexpr auto kFreeHiddenChats = std::size_t(1);
inline constexpr auto kFreeHiddenAccounts = std::size_t(0);
inline constexpr auto kPerpetualPremiumUntilMs = std::int64_t(4'102'444'800'000);

enum class PremiumAccess { Unknown, Inactive, Active };

struct PremiumSnapshot {
	PremiumAccess access = PremiumAccess::Unknown;
	std::int64_t displayUntilMs = 0;
	std::optional<std::int64_t> deadlineMonotonicMs;
	bool operator==(const PremiumSnapshot&) const = default;
};

class PremiumClock final {
public:
	bool apply(const Sync::Backend::MeReply &reply, std::int64_t monotonicMs);
	[[nodiscard]] PremiumSnapshot snapshot(std::int64_t monotonicMs);
	void clear();

private:
	bool observe(std::int64_t monotonicMs);

	PremiumSnapshot _snapshot;
	std::optional<std::int64_t> _lastObservedMs;
};

enum class EntryDecision { Allowed, RenewOrReveal };

struct HiddenLimits {
	bool chatsOverLimit = false;
	bool accountsOverLimit = false;
	EntryDecision entry = EntryDecision::Allowed;
	std::size_t freeChatSlots = kFreeHiddenChats;
};

[[nodiscard]] HiddenLimits EvaluateHiddenLimits(
	bool premiumActive,
	std::size_t hiddenChats,
	std::size_t hiddenAccounts);
[[nodiscard]] bool CanAddChats(
	bool premiumActive,
	std::size_t hiddenChats,
	std::size_t additionalChats);
[[nodiscard]] bool CanHideAccount(
	bool premiumActive,
	bool isSelf,
	bool targetOwnsHiddenAccounts,
	bool alreadyHidden);
[[nodiscard]] bool IsEntryButtonVisible(
	bool requestedVisible,
	bool shortcutConfigured,
	bool shortcutTested);

} // namespace Leemen::Security
