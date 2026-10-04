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
	damaged[3] = 3;
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

void ReservationTests() {
	auto state = PrivateAccountsState();
	const auto empty = EncodePrivateAccounts(state);
	Check(!state.reserveLogin(0, A, false), "premium is required before reserving a hidden login");
	Check(!state.reserveLogin(0, {}, true), "zero owner cannot reserve a login");
	Check(!state.reserveLogin(64, A, true), "out of range slot cannot be truncated to a valid byte");
	Check(EncodePrivateAccounts(state) == empty, "failed reservations do not alter the persisted graph");
	Check(!state.loginBlocks(0, B), "ordinary unreserved slots remain independent");
	Check(state.reserveLogin(0, A, true), "slot zero is valid");
	Check(!state.reserveLogin(0, C, true), "existing reserved slot cannot be reassigned");
	Check(state.reserveLogin(63, C, true), "maximum portable slot is valid");
	Check(state.ownsHiddenAccounts(A), "pending owner cannot itself be hidden by another account");
	Check(state.setHidden(D, A, true, true) == HideAccountResult::TargetOwnsAccounts,
		"pending owner is protected before target identity is known");
	for (const auto id : { A, B, C, AccountIdentity{ B.userId, true } }) {
		Check(state.loginBlocks(0, id), "unbound login blocks every prospective session identity");
	}
	const auto reserved = EncodePrivateAccounts(state);
	Check(!state.completeLogin(0, A), "login cannot bind to its owner");
	Check(!state.completeLogin(0, {}), "login cannot bind zero identity");
	Check(!state.completeLogin(0, { B.userId, true }), "login cannot cross production and test environments");
	Check(!state.completeLogin(2, B), "unreserved slot cannot promote an account");
	Check(EncodePrivateAccounts(state) == reserved, "failed promotion retains the exact crash guard");
	const auto restarted = DecodePrivateAccounts(reserved);
	Check(restarted && restarted->loginBlocks(0, B) && restarted->logins() == state.logins(),
		"crash before identity discovery retains both slot reservations");
	Check(state.completeLogin(0, B), "completion installs graph membership before allowing the matching identity");
	Check(state.isHiddenBy(A, B) && state.isHiddenByAny(B) && !state.loginBlocks(0, B),
		"completed identity still requires the separate hidden-account visibility grant");
	Check(state.loginBlocks(0, D) && state.loginBlocks(0, { B.userId, true }),
		"slot reuse or environment drift never inherits completed authorization");
	Check(state.completeLogin(0, B), "same completed binding is idempotent");
	Check(!state.completeLogin(0, D), "completed binding cannot silently switch identity");
	const auto beforeCancel = state;
	state.cancelLogin(0);
	Check(state.loginBlocks(0, B) && !state.completeLogin(0, B),
		"cancelled login rejects a late matching authorization response");
	const auto cancelled = DecodePrivateAccounts(EncodePrivateAccounts(state));
	Check(cancelled && cancelled->logins().at(0).cancelling && cancelled->loginBlocks(0, B),
		"crash after cancellation keeps the completed account blocked");
	state = beforeCancel;
	Check(!state.logins().at(0).cancelling && state.logins().at(0).completed == B,
		"whole-state rollback restores reservation flags and completed binding");
	const auto protectedBytes = EncodePrivateAccounts(state);
	auto graphOnly = state.snapshot();
	graphOnly[A].hidden.erase(B);
	graphOnly.erase(A);
	Check(!state.restore(std::move(graphOnly)), "graph-only rollback cannot orphan a completed slot binding");
	Check(EncodePrivateAccounts(state) == protectedBytes, "invalid graph replacement preserves all protection");
	Check(state.setHidden(A, B, false, false) == HideAccountResult::Changed,
		"explicit reveal removes completed slot guard together with its owning edge");
	Check(!state.logins().contains(0) && state.logins().contains(63),
		"reveal leaves unrelated pending login intact");
	state = beforeCancel;
	Check(EncodePrivateAccounts(state) == protectedBytes,
		"failed persistence can restore graph and slot binding as one snapshot");
	state.removeAccount(A);
	Check(state.logins().contains(0) && !state.logins().at(0).completed && state.loginBlocks(0, B),
		"owner removal leaves an orphan slot quarantined until logout is verified");
	const auto orphan = DecodePrivateAccounts(EncodePrivateAccounts(state));
	Check(orphan && orphan->loginBlocks(0, B) && orphan->logins().at(0).owner == A,
		"orphan quarantine remains restorable without inventing a public account");
	state.cancelLogin(0);
	state.releaseLogin(0);
	Check(!state.logins().contains(0) && state.logins().contains(63),
		"verified cleanup releases only the requested slot");
	auto test = PrivateAccountsState();
	Check(test.reserveLogin(1, { A.userId, true }, true)
		&& test.completeLogin(1, { B.userId, true }), "test environment can bind within its own namespace");
	Check(test.loginBlocks(1, B), "production identity cannot reuse test authorization");
}

void ReservationCapacityTests() {
	auto state = PrivateAccountsState();
	for (auto slot = std::uint32_t(0); slot != kMaxPrivateAccounts; ++slot) {
		Check(state.reserveLogin(slot, { slot + 1, false }, true), "bounded distinct pending owners accepted");
	}
	const auto full = EncodePrivateAccounts(state);
	Check(DecodePrivateAccounts(full).has_value(), "maximum orphan reservation set is readable");
	const auto extra = AccountIdentity{ kMaxPrivateAccounts + 1, false };
	Check(!state.setSwitchPin(extra, LocalPin()), "PIN capacity includes owners of pending logins");
	Check(state.setHidden({ 1, false }, extra, true, true) == HideAccountResult::Capacity,
		"hidden target capacity includes pending owner identities");
	Check(!state.completeLogin(0, extra), "completion cannot overflow identity capacity");
	Check(EncodePrivateAccounts(state) == full, "capacity errors do not create an unreadable journal");
	state.releaseLogin(63);
	Check(state.setSwitchPin(extra, LocalPin()), "verified release makes exactly one identity slot available");
	Check(DecodePrivateAccounts(EncodePrivateAccounts(state)).has_value(),
		"mixed graph and orphan reservations stay within total identity bound");
	auto tooMany = state.logins();
	tooMany.emplace(63, PrivateAccountLogin{ { 1000, false }, std::nullopt });
	const auto mixed = EncodePrivateAccounts(state);
	Check(!state.restoreLogins(std::move(tooMany)), "restoring reservations cannot exceed graph-plus-orphan capacity");
	Check(EncodePrivateAccounts(state) == mixed, "failed reservation restore is atomic");
}

void ReservationStartupTests() {
	auto state = PrivateAccountsState();
	Check(state.reserveLogin(1, A, true), "startup reservation fixture");
	const auto pending = EncodePrivateAccounts(state);
	auto accounts = PrivateAccountSlots{
		{ 0, { A, false } },
		{ 1, { std::nullopt, false } },
	};
	Check(state.reconcileStartup(accounts), "unfinished login restores beside its public owner");
	Check(EncodePrivateAccounts(state) == pending, "restart without authorization keeps exact reservation");
	accounts[1].identity = B;
	Check(state.reconcileStartup(accounts) && state.isHiddenBy(A, B),
		"saved authorization is hidden before the first session can be published");
	const auto bound = EncodePrivateAccounts(state);
	Check(state.reconcileStartup(accounts) && EncodePrivateAccounts(state) == bound,
		"repeated startup reconciliation is idempotent");
	accounts[1].identity = C;
	Check(!state.reconcileStartup(accounts) && EncodePrivateAccounts(state) == bound,
		"slot rebound to another identity fails without altering protection");
	accounts[1].identity = AccountIdentity{ B.userId, true };
	Check(!state.reconcileStartup(accounts), "session and configuration environment disagreement fails closed");
	accounts[1].testEnvironment = true;
	Check(!state.reconcileStartup(accounts), "reserved slot environment cannot change with the session");
	accounts.erase(1);
	Check(!state.reconcileStartup(accounts), "missing reserved authorization file cannot release the slot");
	accounts[1] = { B, false };
	accounts.erase(0);
	Check(!state.reconcileStartup(accounts), "missing owner keeps unfinished cleanup quarantined");
	state.cancelLogin(1);
	Check(!state.reconcileStartup(accounts), "orphan cleanup alone cannot provide a public startup session");
	accounts[0] = { std::nullopt, false };
	Check(state.reconcileStartup(accounts) && state.loginBlocks(1, B),
		"orphan cancellation resumes cleanup while a separate public login remains usable");
	const auto cancelling = EncodePrivateAccounts(state);
	accounts[1].identity = C;
	Check(!state.reconcileStartup(accounts) && EncodePrivateAccounts(state) == cancelling,
		"cancellation never accepts a different completed identity");
	accounts[1].identity.reset();
	Check(state.reconcileStartup(accounts), "cancelled empty slot survives restart until durable removal");
	auto malformed = accounts;
	malformed[64] = { D, false };
	Check(!state.reconcileStartup(malformed), "out of range persisted slot rejected");
	malformed = accounts;
	malformed[0].identity = AccountIdentity{};
	Check(!state.reconcileStartup(malformed), "present zero session identity is not an empty login slot");
	malformed = accounts;
	malformed[0].identity = A;
	malformed[2] = { A, false };
	Check(!state.reconcileStartup(malformed), "duplicate authorization identities cannot become separate public slots");
	auto interrupted = PrivateAccountsState();
	Check(interrupted.reserveLogin(1, A, true) && interrupted.reserveLogin(2, C, true),
		"atomic reconciliation fixture with two owner identities");
	const auto before = EncodePrivateAccounts(interrupted);
	const auto partiallyValid = PrivateAccountSlots{
		{ 0, { A, false } },
		{ 1, { B, false } },
		{ 2, { D, false } },
	};
	Check(!interrupted.reconcileStartup(partiallyValid)
		&& EncodePrivateAccounts(interrupted) == before,
		"later missing owner rolls back every earlier promotion as one transaction");
	auto namespaceState = PrivateAccountsState();
	Check(namespaceState.reserveLogin(1, { A.userId, true }, true), "test startup fixture");
	const auto testAccounts = PrivateAccountSlots{
		{ 0, { AccountIdentity{ A.userId, true }, true } },
		{ 1, { AccountIdentity{ B.userId, true }, true } },
	};
	Check(namespaceState.reconcileStartup(testAccounts)
		&& namespaceState.isHiddenBy({ A.userId, true }, { B.userId, true }),
		"test namespace startup retains exact owner and target environment");
}

void ReservationCodecTests() {
	auto graph = PrivateAccountsState();
	Check(graph.setHidden(A, B, true, true) == HideAccountResult::Changed, "migration fixture");
	auto legacy = EncodePrivateAccounts(graph);
	legacy[3] = 1;
	legacy.resize(legacy.size() - 2);
	const auto migrated = DecodePrivateAccounts(legacy);
	Check(migrated && migrated->isHiddenBy(A, B) && migrated->logins().empty(),
		"LAC1 migration keeps hidden memberships and starts with no fabricated login intents");
	Check(EncodePrivateAccounts(*migrated)[3] == 2, "legacy state rewrites as LAC2");
	legacy.push_back(0);
	Check(!DecodePrivateAccounts(legacy), "LAC1 trailing bytes cannot be reinterpreted as login markers");
	auto pending = PrivateAccountsState();
	Check(pending.reserveLogin(0, A, true), "pending codec fixture");
	const auto bytes = EncodePrivateAccounts(pending);
	Check(bytes.size() == 19, "minimal reservation fixture has the documented bounded envelope");
	for (auto length = std::size_t(0); length < bytes.size(); ++length) {
		Check(!DecodePrivateAccounts(std::span(bytes).first(length)), "truncated pending reservation rejected");
	}
	for (const auto slot : { 64, 255 }) {
		auto damaged = bytes;
		damaged[8] = static_cast<unsigned char>(slot);
		Check(!DecodePrivateAccounts(damaged), "nonexistent encoded slot rejected");
	}
	for (const auto flag : { 4, 7, 255 }) {
		auto damaged = bytes;
		damaged[18] = static_cast<unsigned char>(flag);
		Check(!DecodePrivateAccounts(damaged), "unknown completion and cancellation bits rejected");
	}
	auto damaged = bytes;
	damaged[18] = 1;
	Check(!DecodePrivateAccounts(damaged), "completed flag without identity fails closed");
	damaged = bytes;
	damaged[17] = 2;
	Check(!DecodePrivateAccounts(damaged), "reservation owner environment must be canonical");
	damaged = bytes;
	std::fill(damaged.begin() + 9, damaged.begin() + 17, std::uint8_t(0));
	Check(!DecodePrivateAccounts(damaged), "zero reservation owner rejected");
	damaged = bytes;
	damaged[7] = 2;
	damaged.insert(damaged.end(), bytes.begin() + 8, bytes.end());
	Check(!DecodePrivateAccounts(damaged), "duplicate reservation slots rejected");
	damaged = bytes;
	damaged[6] = 1;
	Check(!DecodePrivateAccounts(damaged), "oversized reservation count rejected before allocation");
	Check(pending.completeLogin(0, B), "completed codec fixture");
	pending.cancelLogin(0);
	const auto complete = EncodePrivateAccounts(pending);
	const auto copy = DecodePrivateAccounts(complete);
	Check(copy && copy->logins() == pending.logins() && copy->isHiddenBy(A, B),
		"completed and cancelling bits survive restart together");
	for (auto length = std::size_t(0); length < complete.size(); ++length) {
		Check(!DecodePrivateAccounts(std::span(complete).first(length)), "every completed journal truncation rejected");
	}
	damaged = complete;
	damaged.back() = 1;
	Check(!DecodePrivateAccounts(damaged), "completed identity environment cannot differ from owner");
	damaged = complete;
	damaged[damaged.size() - 2] = 201;
	Check(!DecodePrivateAccounts(damaged), "completed identity requires an actual hidden graph edge");
	for (auto offset = std::size_t(0); offset < complete.size(); ++offset) {
		for (const auto value : { 0, 1, 2, 63, 64, 127, 255 }) {
			damaged = complete;
			damaged[offset] = static_cast<unsigned char>(value);
			if (const auto decoded = DecodePrivateAccounts(damaged)) {
				const auto encoded = EncodePrivateAccounts(*decoded);
				const auto again = DecodePrivateAccounts(encoded);
				Check(again && EncodePrivateAccounts(*again) == encoded,
					"every accepted mutated journal has a stable, readable canonical representation");
			}
		}
	}
}

} // namespace

int main() {
	GraphTests();
	CodecTests();
	ReservationTests();
	ReservationCapacityTests();
	ReservationStartupTests();
	ReservationCodecTests();
	std::cout << "Private accounts checks passed: " << Checks << '\n';
}
