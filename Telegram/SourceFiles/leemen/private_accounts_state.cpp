#include "leemen/private_accounts_state.h"

#include <algorithm>
#include <array>
#include <utility>

namespace Leemen {
namespace {

constexpr auto kMagic = std::array<unsigned char, 4>{ 'L', 'A', 'C', 1 };

std::set<AccountIdentity> Identities(const PrivateAccountsSnapshot &snapshot) {
	auto result = std::set<AccountIdentity>();
	for (const auto &[owner, value] : snapshot) {
		result.emplace(owner);
		result.insert(value.hidden.begin(), value.hidden.end());
	}
	return result;
}

bool Reaches(
		const PrivateAccountsSnapshot &snapshot,
		AccountIdentity start,
		AccountIdentity target,
		std::set<AccountIdentity> &visited) {
	if (start == target) return true;
	if (!visited.emplace(start).second) return false;
	const auto i = snapshot.find(start);
	if (i == snapshot.end()) return false;
	for (const auto child : i->second.hidden) {
		if (Reaches(snapshot, child, target, visited)) return true;
	}
	return false;
}

bool ValidSnapshot(const PrivateAccountsSnapshot &snapshot) {
	if (snapshot.size() > kMaxPrivateAccounts) return false;
	for (const auto &[owner, value] : snapshot) {
		if (!ValidAccountIdentity(owner) || value.hidden.size() > kMaxPrivateAccounts
			|| (value.hidden.empty() && !value.switchPin)) return false;
		for (const auto target : value.hidden) {
			if (!ValidAccountIdentity(target)) return false;
			auto visited = std::set<AccountIdentity>();
			if (Reaches(snapshot, target, owner, visited)) return false;
		}
	}
	return Identities(snapshot).size() <= kMaxPrivateAccounts;
}

void Put(std::vector<unsigned char> &bytes, std::uint64_t value, std::size_t size) {
	for (auto i = size; i > 0; --i) {
		bytes.push_back(static_cast<unsigned char>(value >> ((i - 1) * 8)));
	}
}

void PutIdentity(std::vector<unsigned char> &bytes, AccountIdentity value) {
	Put(bytes, value.userId, 8);
	Put(bytes, value.testEnvironment ? 1 : 0, 1);
}

class Reader {
public:
	explicit Reader(std::span<const unsigned char> bytes) : _bytes(bytes) {
	}
	std::optional<std::uint64_t> integer(std::size_t size) {
		if (_bytes.size() < size) return std::nullopt;
		auto result = std::uint64_t(0);
		for (const auto byte : _bytes.first(size)) result = (result << 8) | byte;
		_bytes = _bytes.subspan(size);
		return result;
	}
	std::optional<AccountIdentity> identity() {
		const auto user = integer(8);
		const auto environment = integer(1);
		if (!user || !environment || *environment > 1) return std::nullopt;
		const auto result = AccountIdentity{ *user, *environment == 1 };
		return ValidAccountIdentity(result) ? std::make_optional(result) : std::nullopt;
	}
	bool read(std::span<unsigned char> result) {
		if (_bytes.size() < result.size()) return false;
		std::ranges::copy(_bytes.first(result.size()), result.begin());
		_bytes = _bytes.subspan(result.size());
		return true;
	}
	bool done() const { return _bytes.empty(); }

private:
	std::span<const unsigned char> _bytes;
};

} // namespace

bool ValidAccountIdentity(AccountIdentity identity) {
	return identity.userId > 0 && identity.userId <= 9'007'199'254'740'991ULL;
}

const PrivateAccountsSnapshot &PrivateAccountsState::snapshot() const {
	return _owners;
}

bool PrivateAccountsState::restore(PrivateAccountsSnapshot snapshot) {
	if (!ValidSnapshot(snapshot)) return false;
	_owners = std::move(snapshot);
	return true;
}

HideAccountResult PrivateAccountsState::setHidden(
		AccountIdentity owner,
		AccountIdentity target,
		bool hidden,
		bool premiumActive) {
	if (!ValidAccountIdentity(owner) || !ValidAccountIdentity(target) || owner == target) {
		return HideAccountResult::Invalid;
	}
	if (isHiddenBy(owner, target) == hidden) return HideAccountResult::Unchanged;
	if (hidden) {
		if (!premiumActive) return HideAccountResult::NeedsPremium;
		auto visited = std::set<AccountIdentity>();
		if (Reaches(_owners, target, owner, visited)) return HideAccountResult::WouldCycle;
		if (ownsHiddenAccounts(target)) return HideAccountResult::TargetOwnsAccounts;
		auto identities = Identities(_owners);
		identities.emplace(owner);
		identities.emplace(target);
		if (identities.size() > kMaxPrivateAccounts) return HideAccountResult::Capacity;
		_owners[owner].hidden.emplace(target);
	} else {
		const auto i = _owners.find(owner);
		i->second.hidden.erase(target);
		if (i->second.hidden.empty() && !i->second.switchPin) _owners.erase(i);
	}
	return HideAccountResult::Changed;
}

bool PrivateAccountsState::setSwitchPin(AccountIdentity owner, std::optional<LocalPin> pin) {
	if (!ValidAccountIdentity(owner)) return false;
	if (pin) {
		auto identities = Identities(_owners);
		identities.emplace(owner);
		if (identities.size() > kMaxPrivateAccounts) return false;
		_owners[owner].switchPin = std::move(pin);
	} else if (const auto i = _owners.find(owner); i != _owners.end()) {
		i->second.switchPin.reset();
		if (i->second.hidden.empty()) _owners.erase(i);
	}
	return true;
}

const LocalPin *PrivateAccountsState::switchPin(AccountIdentity owner) const {
	const auto i = _owners.find(owner);
	return (i != _owners.end() && i->second.switchPin) ? &*i->second.switchPin : nullptr;
}

bool PrivateAccountsState::isHiddenBy(AccountIdentity owner, AccountIdentity target) const {
	const auto i = _owners.find(owner);
	return i != _owners.end() && i->second.hidden.contains(target);
}

bool PrivateAccountsState::isHiddenByAny(AccountIdentity target) const {
	return std::ranges::any_of(_owners, [&](const auto &entry) {
		return entry.second.hidden.contains(target);
	});
}

bool PrivateAccountsState::ownsHiddenAccounts(AccountIdentity owner) const {
	const auto i = _owners.find(owner);
	return i != _owners.end() && !i->second.hidden.empty();
}

bool PrivateAccountsState::hiddenFrom(
		AccountIdentity viewer,
		AccountIdentity target,
		bool viewerPrivateSpaceActive) const {
	if (viewer == target) return false;
	return isHiddenBy(viewer, target) ? !viewerPrivateSpaceActive : isHiddenByAny(target);
}

std::optional<AccountIdentity> PrivateAccountsState::safeAccount(
		std::span<const AccountIdentity> available,
		std::optional<AccountIdentity> preferred) const {
	if (preferred && ValidAccountIdentity(*preferred) && !isHiddenByAny(*preferred)
		&& std::ranges::find(available, *preferred) != available.end()) return preferred;
	for (const auto account : available) {
		if (ValidAccountIdentity(account) && !isHiddenByAny(account)) return account;
	}
	return std::nullopt;
}

std::vector<AccountIdentity> PrivateAccountsState::logoutClosure(AccountIdentity owner) const {
	auto pending = std::vector<AccountIdentity>{ owner };
	auto visited = std::set<AccountIdentity>{ owner };
	auto result = std::vector<AccountIdentity>();
	while (!pending.empty()) {
		const auto current = pending.back();
		pending.pop_back();
		const auto i = _owners.find(current);
		if (i == _owners.end()) continue;
		for (const auto child : i->second.hidden) {
			if (visited.emplace(child).second) {
				pending.push_back(child);
				result.push_back(child);
			}
		}
	}
	return result;
}

void PrivateAccountsState::removeAccount(AccountIdentity account) {
	_owners.erase(account);
	for (auto i = _owners.begin(); i != _owners.end();) {
		i->second.hidden.erase(account);
		if (i->second.hidden.empty() && !i->second.switchPin) i = _owners.erase(i);
		else ++i;
	}
}

std::vector<unsigned char> EncodePrivateAccounts(const PrivateAccountsState &state) {
	auto result = std::vector<unsigned char>(kMagic.begin(), kMagic.end());
	Put(result, state.snapshot().size(), 2);
	for (const auto &[owner, value] : state.snapshot()) {
		PutIdentity(result, owner);
		Put(result, value.switchPin ? 1 : 0, 1);
		if (value.switchPin) {
			result.insert(result.end(), value.switchPin->salt.begin(), value.switchPin->salt.end());
			result.insert(result.end(), value.switchPin->digest.begin(), value.switchPin->digest.end());
		}
		Put(result, value.hidden.size(), 2);
		for (const auto child : value.hidden) PutIdentity(result, child);
	}
	return result;
}

std::optional<PrivateAccountsState> DecodePrivateAccounts(std::span<const unsigned char> bytes) {
	if (bytes.size() < kMagic.size() || bytes.size() > kMaxPrivateAccountsBytes
		|| !std::ranges::equal(bytes.first(kMagic.size()), kMagic)) return std::nullopt;
	auto reader = Reader(bytes.subspan(kMagic.size()));
	const auto count = reader.integer(2);
	if (!count || *count > kMaxPrivateAccounts) return std::nullopt;
	auto snapshot = PrivateAccountsSnapshot();
	for (auto index = std::uint64_t(0); index != *count; ++index) {
		const auto owner = reader.identity();
		const auto hasPin = reader.integer(1);
		if (!owner || !hasPin || *hasPin > 1) return std::nullopt;
		auto value = PrivateAccountOwner();
		if (*hasPin) {
			value.switchPin = LocalPin();
			if (!reader.read(value.switchPin->salt) || !reader.read(value.switchPin->digest)) return std::nullopt;
		}
		const auto children = reader.integer(2);
		if (!children || *children > kMaxPrivateAccounts) return std::nullopt;
		for (auto child = std::uint64_t(0); child != *children; ++child) {
			const auto target = reader.identity();
			if (!target || !value.hidden.emplace(*target).second) return std::nullopt;
		}
		if (!snapshot.emplace(*owner, std::move(value)).second) return std::nullopt;
	}
	if (!reader.done()) return std::nullopt;
	auto result = PrivateAccountsState();
	return result.restore(std::move(snapshot)) ? std::make_optional(std::move(result)) : std::nullopt;
}

} // namespace Leemen
