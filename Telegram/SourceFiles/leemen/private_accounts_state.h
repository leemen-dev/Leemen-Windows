#pragma once

#include "leemen/local_pin.h"

#include <compare>
#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <vector>

namespace Leemen {

inline constexpr auto kMaxPrivateAccounts = std::size_t(64);
inline constexpr auto kMaxPrivateAccountsBytes = std::size_t(64 * 1024);

struct AccountIdentity {
	std::uint64_t userId = 0;
	bool testEnvironment = false;
	std::strong_ordering operator<=>(const AccountIdentity&) const = default;
};

struct PrivateAccountOwner {
	std::set<AccountIdentity> hidden;
	std::optional<LocalPin> switchPin;
};

using PrivateAccountsSnapshot = std::map<AccountIdentity, PrivateAccountOwner>;

enum class HideAccountResult {
	Changed,
	Unchanged,
	Invalid,
	NeedsPremium,
	TargetOwnsAccounts,
	WouldCycle,
	Capacity,
};

class PrivateAccountsState final {
public:
	[[nodiscard]] const PrivateAccountsSnapshot &snapshot() const;
	[[nodiscard]] bool restore(PrivateAccountsSnapshot snapshot);
	[[nodiscard]] HideAccountResult setHidden(
		AccountIdentity owner,
		AccountIdentity target,
		bool hidden,
		bool premiumActive);
	[[nodiscard]] bool setSwitchPin(AccountIdentity owner, std::optional<LocalPin> pin);
	[[nodiscard]] const LocalPin *switchPin(AccountIdentity owner) const;
	[[nodiscard]] bool isHiddenBy(AccountIdentity owner, AccountIdentity target) const;
	[[nodiscard]] bool isHiddenByAny(AccountIdentity target) const;
	[[nodiscard]] bool ownsHiddenAccounts(AccountIdentity owner) const;
	[[nodiscard]] bool hiddenFrom(
		AccountIdentity viewer,
		AccountIdentity target,
		bool viewerPrivateSpaceActive) const;
	[[nodiscard]] std::optional<AccountIdentity> safeAccount(
		std::span<const AccountIdentity> available,
		std::optional<AccountIdentity> preferred = std::nullopt) const;
	[[nodiscard]] std::vector<AccountIdentity> logoutClosure(AccountIdentity owner) const;
	void removeAccount(AccountIdentity account);

private:
	PrivateAccountsSnapshot _owners;
};

[[nodiscard]] bool ValidAccountIdentity(AccountIdentity identity);
[[nodiscard]] std::vector<unsigned char> EncodePrivateAccounts(const PrivateAccountsState &state);
[[nodiscard]] std::optional<PrivateAccountsState> DecodePrivateAccounts(
	std::span<const unsigned char> bytes);

} // namespace Leemen
