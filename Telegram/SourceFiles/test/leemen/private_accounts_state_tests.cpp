#include "leemen/private_accounts_state.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>

namespace {

using namespace Leemen;
constexpr auto A = AccountIdentity{ 100, false };
constexpr auto B = AccountIdentity{ 200, false };
constexpr auto C = AccountIdentity{ 300, false };
constexpr auto D = AccountIdentity{ 400, false };
auto Checks = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

void GraphTests() {
	auto state = PrivateAccountsState();
	Check(state.setHidden(A, B, true, false) == HideAccountResult::NeedsPremium, "hidden accounts require Leemen premium");
	Check(state.setHidden(A, A, true, true) == HideAccountResult::Invalid, "cannot hide self");
	Check(state.setHidden({}, B, true, true) == HideAccountResult::Invalid, "owner must have stable account identity");
	Check(state.setHidden(A, B, true, true) == HideAccountResult::Changed, "owner hides target");
	Check(state.setHidden(A, B, true, false) == HideAccountResult::Unchanged, "expiry never reveals existing hidden account");
	Check(state.hiddenFrom(A, B, false), "owner OFF hides account");
	Check(!state.hiddenFrom(A, B, true), "owner REAL can see account");
	Check(state.hiddenFrom(C, B, true), "other REAL owner cannot see private account");
	Check(!state.hiddenFrom(B, B, false), "self visibility exception");
	Check(state.isHiddenByAny(B), "notification self backstop independent of viewer");
	Check(!state.hiddenFrom(A, AccountIdentity{ B.userId, true }, false), "test and production IDs distinct");
	Check(state.setHidden(B, A, true, true) == HideAccountResult::WouldCycle, "reciprocal hide forbidden");
	Check(state.setHidden(C, A, true, true) == HideAccountResult::TargetOwnsAccounts, "cannot hide existing owner");
	Check(state.setHidden(B, C, true, true) == HideAccountResult::Changed, "Android allows hidden account to become owner later");
	Check(state.setHidden(C, A, true, true) == HideAccountResult::WouldCycle, "long cycle rejected");
	Check(state.setHidden(D, C, true, true) == HideAccountResult::Changed, "multiple owners supported");
	const auto closure = state.logoutClosure(A);
	Check(closure.size() == 2 && std::ranges::find(closure, B) != closure.end()
		&& std::ranges::find(closure, C) != closure.end(), "logout computes descendant closure before graph deletion");
	const auto available = std::array{ B, C, D, A };
	Check(state.safeAccount(available, B) == D, "cold start replaces hidden last account");
	Check(state.safeAccount(available, A) == A, "safe preferred owner retained");
	Check(!state.safeAccount(std::array{ B, C }), "no safe candidate fails closed");
	Check(!state.safeAccount({}), "empty account set has no fallback");
	Check(state.setHidden(A, B, false, false) == HideAccountResult::Changed, "revealing always permitted after expiry");
	Check(!state.isHiddenByAny(B), "explicit reveal removes edge");
	Check(state.setHidden(A, B, false, false) == HideAccountResult::Unchanged, "reveal idempotent");
	state.removeAccount(C);
	Check(!state.ownsHiddenAccounts(B) && !state.ownsHiddenAccounts(D), "target logout removes all inbound edges");
	Check(state.snapshot().empty(), "no stale graph metadata after all targets removed");
	const auto pin = LocalPin();
	Check(state.setSwitchPin(A, pin) && state.switchPin(A), "owner switch PIN independent of memberships");
	Check(!state.switchPin(B), "PIN belongs to owner rather than hidden target");
	Check(state.setSwitchPin(A, std::nullopt) && state.snapshot().empty(), "clear PIN drops empty owner record");
	for (auto i = std::uint64_t(1); i <= kMaxPrivateAccounts; ++i) {
		Check(state.setSwitchPin({ i, false }, pin), "bounded valid account set accepted");
	}
	Check(!state.setSwitchPin({ kMaxPrivateAccounts + 1, false }, pin), "owner capacity bounded");
	Check(state.setHidden({ 1, false }, { kMaxPrivateAccounts + 1, false }, true, true) == HideAccountResult::Capacity, "target capacity bounded");
}

void CodecTests() {
	auto state = PrivateAccountsState();
	Check(state.setHidden(A, B, true, true) == HideAccountResult::Changed, "fixture membership");
	auto pin = LocalPin();
	pin.salt.fill(0x11);
	pin.digest.fill(0x22);
	Check(state.setSwitchPin(A, pin), "fixture owner pin");
	const auto bytes = EncodePrivateAccounts(state);
	const auto copy = DecodePrivateAccounts(bytes);
	Check(copy && copy->isHiddenBy(A, B), "strict local codec preserves graph");
	Check(copy->switchPin(A) && copy->switchPin(A)->salt == pin.salt
		&& copy->switchPin(A)->digest == pin.digest, "PBKDF verifier preserved without plaintext PIN");
	Check(EncodePrivateAccounts(*copy) == bytes, "canonical re-encoding stable");
	for (auto length = std::size_t(0); length < bytes.size(); ++length) {
		Check(!DecodePrivateAccounts(std::span(bytes).first(length)), "truncated journal rejected");
	}
	auto damaged = bytes;
	damaged.push_back(0);
	Check(!DecodePrivateAccounts(damaged), "trailing journal data rejected");
	damaged = bytes;
	damaged[3] = 2;
	Check(!DecodePrivateAccounts(damaged), "unknown schema rejected");
	damaged = bytes;
	damaged[14] = 2;
	Check(!DecodePrivateAccounts(damaged), "unknown environment rejected");
	damaged = bytes;
	damaged[15] = 2;
	Check(!DecodePrivateAccounts(damaged), "noncanonical optional pin flag rejected");
	damaged = bytes;
	damaged[4] = 1;
	Check(!DecodePrivateAccounts(damaged), "oversized owner count rejected");
	Check(!DecodePrivateAccounts(std::vector<unsigned char>(kMaxPrivateAccountsBytes + 1)), "journal byte bound");
	auto invalid = PrivateAccountsSnapshot();
	invalid[A].hidden.emplace(B);
	invalid[B].hidden.emplace(C);
	invalid[C].hidden.emplace(A);
	Check(!state.restore(invalid), "corrupt cyclic journal rejected");
	Check(state.isHiddenBy(A, B) && state.switchPin(A), "failed restore does not partially replace protected state");
	invalid.clear();
	invalid[A].hidden.emplace(A);
	Check(!state.restore(invalid), "self edge rejected during restore");
	invalid.clear();
	invalid[A].hidden.emplace(AccountIdentity{});
	Check(!state.restore(invalid), "invalid user rejected during restore");
	invalid.clear();
	invalid[A] = {};
	Check(!state.restore(invalid), "empty redundant owner record rejected");
	Check(!ValidAccountIdentity({ 0, false })
		&& !ValidAccountIdentity({ std::numeric_limits<std::uint64_t>::max(), false }), "identity integer bounds");
	Check(ValidAccountIdentity({ 9'007'199'254'740'991ULL, true }), "maximum supported stable identity");
	const auto empty = DecodePrivateAccounts(EncodePrivateAccounts(PrivateAccountsState()));
	Check(empty && empty->snapshot().empty(), "explicit empty state valid");
}

} // namespace

int main() {
	GraphTests();
	CodecTests();
	std::cout << "Private accounts checks passed: " << Checks << '\n';
}
