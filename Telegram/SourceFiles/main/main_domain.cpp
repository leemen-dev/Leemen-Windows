/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "main/main_domain.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "core/shortcuts.h"
#include "core/crash_reports.h"
#include "main/main_account.h"
#include "main/main_session.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/leemen_private_accounts_box.h"
#include "data/data_session.h"
#include "data/data_changes.h"
#include "data/data_user.h"
#include "mtproto/mtproto_config.h"
#include "mtproto/mtproto_dc_options.h"
#include "storage/storage_domain.h"
#include "storage/storage_account.h"
#include "storage/localstorage.h"
#include "export/export_settings.h"
#include "window/notifications_manager.h"
#include "window/window_controller.h"
#include "data/data_peer_values.h" // Data::AmPremiumValue.

namespace Main {

Domain::Domain(const QString &dataName)
: _dataName(dataName)
, _local(std::make_unique<Storage::Domain>(this, dataName))
, _privateAccounts(std::make_unique<Leemen::PrivateAccounts>(this)) {
	_active.changes(
	) | rpl::take(1) | rpl::on_next([=] {
		// In case we had a legacy passcoded app we start settings here.
		Core::App().startSettingsAndBackground();

		crl::on_main(this, [=] {
			Core::App().notifications().createManager();
		});
	}, _lifetime);

	_active.changes(
	) | rpl::map([](Main::Account *account) {
		return account ? account->sessionValue() : rpl::never<Session*>();
		}) | rpl::flatten_latest(
	) | rpl::map([](Main::Session *session) {
		return session
			? session->changes().peerFlagsValue(
				session->user(),
				Data::PeerUpdate::Flag::Username)
			: rpl::never<Data::PeerUpdate>();
	}) | rpl::flatten_latest(
	) | rpl::on_next([](const Data::PeerUpdate &update) {
		CrashReports::SetAnnotation("Username", Leemen::PrivateAccountNotificationsAllowed(&update.peer->session())
			? update.peer->username() : QString());
	}, _lifetime);
}

Domain::~Domain() = default;

Leemen::PrivateAccounts &Domain::privateAccounts() const {
	return *_privateAccounts;
}

bool Domain::started() const {
	return !_accounts.empty();
}

Storage::StartResult Domain::start(const QByteArray &passcode) {
	Expects(!started());

	_privateAccounts->start();
	const auto result = _local->start(passcode);
	if (result == Storage::StartResult::Success) {
		activateAfterStarting();
		crl::on_main(&Core::App(), [=] { suggestExportIfNeeded(); });
	} else {
		Assert(!started());
	}
	return result;
}

void Domain::finish() {
	_privateAccounts->finish();
	_accountToActivate = -1;
	_active.reset(nullptr);
	base::take(_accounts);
}

void Domain::suggestExportIfNeeded() {
	Expects(started());

	for (const auto &[index, account] : _accounts) {
		if (const auto session = account->maybeSession()) {
			const auto settings = session->local().readExportSettings();
			if (const auto availableAt = settings.availableAt) {
				session->data().suggestStartExport(availableAt);
			}
		}
	}
}

void Domain::accountAddedInStorage(AccountWithIndex accountWithIndex) {
	Expects(accountWithIndex.account != nullptr);

	for (const auto &[index, _] : _accounts) {
		if (index == accountWithIndex.index) {
			Unexpected("Repeated account index.");
		}
	}
	_accounts.push_back(std::move(accountWithIndex));
	_privateAccounts->watchAccount(_accounts.back().account.get());
}

void Domain::activateFromStorage(int index) {
	_accountToActivate = index;
}

int Domain::activeForStorage() const {
	return _accountToActivate;
}

void Domain::resetWithForgottenPasscode() {
	if (_privateAccounts->damaged()) return;
	if (_accounts.empty()) {
		_local->startFromScratch();
		activateAfterStarting();
	} else {
		for (const auto &[index, account] : _accounts) {
			account->logOut();
		}
	}
}

void Domain::activateAfterStarting() {
	Expects(started());

	auto toActivate = _accounts.front().account.get();
	for (const auto &[index, account] : _accounts) {
		if (index == _accountToActivate) {
			toActivate = account.get();
		}
		watchSession(account.get());
	}

	if (const auto safe = _privateAccounts->safeAccount(toActivate)) {
		activate(safe);
	} else {
		Unexpected("No safe account after validated private account startup.");
	}
	removePasscodeIfEmpty();
}

const std::vector<Domain::AccountWithIndex> &Domain::accounts() const {
	return _accounts;
}

std::vector<not_null<Account*>> Domain::orderedAccounts() const {
	const auto order = Core::App().settings().accountsOrder();
	auto accounts = ranges::views::all(
		_accounts
	) | ranges::views::transform([](const Domain::AccountWithIndex &a) {
		return not_null{ a.account.get() };
	}) | ranges::to_vector;
	ranges::stable_sort(accounts, [&](
			not_null<Account*> a,
			not_null<Account*> b) {
		const auto aIt = a->sessionExists()
			? ranges::find(order, a->session().uniqueId())
			: end(order);
		const auto bIt = b->sessionExists()
			? ranges::find(order, b->session().uniqueId())
			: end(order);
		return aIt < bIt;
	});
	return accounts;
}

rpl::producer<> Domain::accountsChanges() const {
	return _accountsChanges.events();
}

std::vector<not_null<Account*>> Domain::nonHiddenAccounts() const {
	auto result = orderedAccounts();
	std::erase_if(result, [&](not_null<Account*> account) {
		return _privateAccounts->hidden(account);
	});
	return result;
}

Account *Domain::maybeLastOrSomeAuthedAccount() {
	auto result = (Account*)nullptr;
	for (const auto &[index, account] : _accounts) {
		if (!account->sessionExists() || _privateAccounts->hidden(account.get())) {
			continue;
		} else if (index == _lastActiveIndex) {
			return account.get();
		} else if (!result) {
			result = account.get();
		}
	}
	return result;
}

int Domain::accountsAuthedCount() const {
	auto result = 0;
	for (const auto &[index, account] : _accounts) {
		if (account->sessionExists()) {
			++result;
		}
	}
	return result;
}

rpl::producer<Account*> Domain::activeValue() const {
	return _active.value();
}

Account &Domain::active() const {
	Expects(!_accounts.empty());

	Ensures(_active.current() != nullptr);
	return *_active.current();
}

Account *Domain::maybeActive() const {
	return _active.current();
}

rpl::producer<not_null<Account*>> Domain::activeChanges() const {
	return _active.changes() | rpl::map([](Account *value) {
		return not_null{ value };
	});
}

rpl::producer<Session*> Domain::activeSessionChanges() const {
	return _activeSessions.events();
}

rpl::producer<Session*> Domain::activeSessionValue() const {
	const auto current = _accounts.empty()
		? nullptr
		: active().maybeSession();
	return rpl::single(current) | rpl::then(_activeSessions.events());
}

int Domain::unreadBadge() const {
	return _unreadBadge;
}

bool Domain::unreadBadgeMuted() const {
	return _unreadBadgeMuted;
}

rpl::producer<> Domain::unreadBadgeChanges() const {
	return _unreadBadgeChanges.events();
}

void Domain::notifyUnreadBadgeChanged() {
	for (const auto &[index, account] : _accounts) {
		if (const auto session = account->maybeSession()) {
			session->data().notifyUnreadBadgeChanged();
		}
	}
}

void Domain::updateUnreadBadge() {
	_unreadBadge = 0;
	_unreadBadgeMuted = true;
	for (const auto &[index, account] : _accounts) {
		if (const auto session = account->maybeSession()) {
			if (!Leemen::PrivateAccountNotificationsAllowed(session)) {
				continue;
			}
			const auto data = &session->data();
			_unreadBadge += data->unreadBadge();
			if (!data->unreadBadgeMuted()) {
				_unreadBadgeMuted = false;
			}
		}
	}
	_unreadBadgeChanges.fire({});
}

void Domain::scheduleUpdateUnreadBadge() {
	if (_unreadBadgeUpdateScheduled || Core::Quitting()) {
		return;
	}
	_unreadBadgeUpdateScheduled = true;
	Core::App().postponeCall(crl::guard(&Core::App(), [=] {
		_unreadBadgeUpdateScheduled = false;
		updateUnreadBadge();
	}));
}

not_null<Main::Account*> Domain::add(MTP::Environment environment) {
	return not_null(addImpl(environment, nullptr));
}

Account *Domain::addHidden(not_null<Session*> owner) {
	if (_accounts.size() + _removingAccountIndices.size() >= std::size_t(maxAccounts())) return nullptr;
	return addImpl(owner->account().mtp().environment(), owner);
}

Account *Domain::addImpl(MTP::Environment environment, Session *privateOwner) {
	Expects(started());
	Expects(_accounts.size() + _removingAccountIndices.size() < kPremiumMaxAccounts);

	static const auto cloneConfig = [](const MTP::Config &config) {
		return std::make_unique<MTP::Config>(config);
	};
	auto mainDcId = MTP::Instance::Fields::kNotSetMainDc;
	const auto accountConfig = [&](not_null<Account*> account) {
		mainDcId = account->mtp().mainDcId();
		return cloneConfig(account->mtp().config());
	};
	auto config = [&] {
		if (_active.current()->mtp().environment() == environment) {
			return accountConfig(_active.current());
		}
		for (const auto &[index, account] : _accounts) {
			if (account->mtp().environment() == environment) {
				return accountConfig(account.get());
			}
		}
		return (environment == MTP::Environment::Production)
			? cloneConfig(Core::App().fallbackProductionConfig())
			: std::make_unique<MTP::Config>(environment);
	}();
	auto index = 0;
	while (_removingAccountIndices.contains(index)
		|| ranges::contains(_accounts, index, &AccountWithIndex::index)) {
		++index;
	}
	Assert(index < kPremiumMaxAccounts);
	_accounts.push_back(AccountWithIndex{
		.index = index,
		.account = std::make_unique<Account>(this, _dataName, index)
	});
	const auto account = _accounts.back().account.get();
	if (privateOwner && !_privateAccounts->reserveLogin(privateOwner, account)) {
		_accounts.pop_back();
		return nullptr;
	}
	_privateAccounts->watchAccount(account);
	account->setMtpMainDcId(mainDcId);
	_local->startAdded(account, std::move(config));
	watchSession(account);
	if (privateOwner && !_privateAccounts->persistNewLogin(account)) return nullptr;
	_accountsChanges.fire({});

	auto &settings = Core::App().settings();
	if (_accounts.size() == 2 && !settings.mainMenuAccountsShown()) {
		settings.setMainMenuAccountsShown(true);
		Core::App().saveSettingsDelayed();
	}

	return account;
}

void Domain::addActivated(MTP::Environment environment, bool newWindow) {
	const auto added = [&](not_null<Main::Account*> account) {
		if (newWindow) {
			Core::App().ensureSeparateWindowFor(account);
		} else if (const auto window = Core::App().separateWindowFor(
				account)) {
			window->activate();
		} else {
			activate(account);
		}
	};
	if (accounts().size() + _removingAccountIndices.size() < std::size_t(maxAccounts())) {
		added(add(environment));
	} else {
		for (auto &[index, account] : accounts()) {
			if (!account->sessionExists()
				&& !_privateAccounts->reserved(account.get())
				&& account->mtp().environment() == environment) {
				added(account.get());
				break;
			}
		}
	}
}

void Domain::watchSession(not_null<Account*> account) {
	account->sessionValue(
	) | rpl::filter([=](Session *session) {
		return session != nullptr;
	}) | rpl::on_next([=](Session *session) {
		session->data().unreadBadgeChanges(
		) | rpl::on_next([=] {
			scheduleUpdateUnreadBadge();
		}, session->lifetime());

		Data::AmPremiumValue(
			session
		) | rpl::on_next([=] {
			_lastMaxAccounts = maxAccounts();
		}, session->lifetime());
	}, account->lifetime());

	account->sessionChanges(
	) | rpl::filter([=](Session *session) {
		return !session;
	}) | rpl::on_next([=] {
		scheduleUpdateUnreadBadge();
		closeAccountWindows(account);
		if (!Core::Quitting()) {
			crl::on_main(&Core::App(), [=] {
				removeRedundantAccounts();
			});
		}
	}, account->lifetime());
}

void Domain::closeAccountWindows(not_null<Main::Account*> account) {
	auto another = (Main::Account*)nullptr;
	for (auto i = _accounts.begin(); i != _accounts.end(); ++i) {
		const auto other = not_null(i->account.get());
		if (other == account || _privateAccounts->hidden(other)) {
			continue;
		} else if (Core::App().separateWindowFor(other)) {
			const auto that = Core::App().separateWindowFor(account);
			if (that) {
				that->close();
			}
		} else if (!another
			|| (other->sessionExists() && !another->sessionExists())) {
			another = other;
		}
	}
	if (another) {
		activate(another);
	}
}

bool Domain::removePasscodeIfEmpty() {
	if (_accounts.size() != 1 || _active.current()->sessionExists()) {
		return false;
	}
	Local::reset();

	// We completely logged out, remove the passcode if it was there.
	if (Core::App().passcodeLocked()) {
		Core::App().unlockPasscode();
	}
	if (!_local->hasLocalPasscode()) {
		return false;
	}
	_local->setPasscode(QByteArray());
	Core::App().settings().setSystemUnlockEnabled(false);
	Core::App().saveSettingsDelayed();
	return true;
}

void Domain::removeRedundantAccounts() {
	Expects(started());

	for (const auto &one : _accounts) {
		if (one.account->destroyingSession()) {
			// We were invoked from a crl::on_main drain that a nested
			// event dispatch started from inside that account's own
			// destroySession(). Erasing it now would free the object
			// under its own stack frame. Retry after unwinding.
			crl::on_main(&Core::App(), [=] {
				removeRedundantAccounts();
			});
			return;
		}
	}

	const auto was = _accounts.size();
	for (auto i = _accounts.begin(); i != _accounts.end();) {
		if (Core::App().separateWindowFor(not_null(i->account.get()))
			|| i->account.get() == _active.current()
			|| _privateAccounts->reserved(i->account.get())
			|| i->account->sessionExists()) {
			++i;
			continue;
		}
		checkForLastProductionConfig(i->account.get());
		i = _accounts.erase(i);
	}

	if (!removePasscodeIfEmpty() && _accounts.size() != was) {
		scheduleWriteAccounts();
		_accountsChanges.fire({});
	}
}

bool Domain::removePrivateLogin(not_null<Account*> account) {
	if (account->sessionExists() || account->destroyingSession() || account->loggingOut()
		|| _active.current() == account || Core::App().separateWindowFor(account)) return false;
	const auto i = ranges::find(_accounts, account.get(), [](const AccountWithIndex &entry) {
		return entry.account.get();
	});
	if (i == _accounts.end()) return false;
	const auto position = i - _accounts.begin();
	const auto index = i->index;
	if (!_removingAccountIndices.emplace(index).second) return false;
	const auto releaseIndex = gsl::finally([&] { _removingAccountIndices.erase(index); });
	auto removed = std::move(*i);
	_accounts.erase(i);
	if (!_privateAccounts->releaseRemovedLogin(removed.index)) {
		const auto restorePosition = std::min(position, std::ptrdiff_t(_accounts.size()));
		_accounts.insert(_accounts.begin() + restorePosition, std::move(removed));
		return false;
	}
	removed.account.reset();
	_privateAccounts->lock();
	_accountsChanges.fire({});
	return true;
}

void Domain::checkForLastProductionConfig(
		not_null<Main::Account*> account) {
	const auto mtp = &account->mtp();
	if (mtp->environment() != MTP::Environment::Production) {
		return;
	}
	for (const auto &[index, other] : _accounts) {
		if (other.get() != account
			&& other->mtp().environment() == MTP::Environment::Production) {
			return;
		}
	}
	Core::App().refreshFallbackProductionConfig(mtp->config());
}

void Domain::maybeActivate(not_null<Main::Account*> account) {
	if (Core::App().separateWindowFor(account)) {
		activate(account);
	} else {
		Core::App().preventOrInvoke(crl::guard(account, [=] {
			activate(account);
		}));
	}
}

void Domain::activate(not_null<Main::Account*> account) {
	if (!_privateAccounts->canActivate(account)) {
		Leemen::ShowPrivateAccountSwitch(account);
		return;
	}
	if (const auto window = Core::App().separateWindowFor(account)) {
		window->activate();
	}
	if (_active.current() == account.get()) {
		return;
	}
	const auto i = ranges::find(_accounts, account.get(), [](
			const AccountWithIndex &value) {
		return value.account.get();
	});
	Assert(i != end(_accounts));
	const auto changed = (_accountToActivate != i->index);
	auto wasAuthed = false;

	_activeLifetime.destroy();
	if (_active.current()) {
		_lastActiveIndex = _accountToActivate;
		wasAuthed = _active.current()->sessionExists();
	}
	_accountToActivate = i->index;
	_active = account.get();
	_active.current()->sessionValue(
	) | rpl::start_to_stream(_activeSessions, _activeLifetime);

	if (changed) {
		if (wasAuthed) {
			scheduleWriteAccounts();
		} else {
			crl::on_main(&Core::App(), [=] {
				removeRedundantAccounts();
			});
		}
	}
}

void Domain::scheduleWriteAccounts() {
	if (_writeAccountsScheduled) {
		return;
	}
	_writeAccountsScheduled = true;
	crl::on_main(&Core::App(), [=] {
		_writeAccountsScheduled = false;
		_local->writeAccounts();
	});
}

int Domain::maxAccounts() const {
	const auto premiumCount = ranges::count_if(accounts(), [](
			const Main::Domain::AccountWithIndex &d) {
		return d.account->sessionExists()
			&& (d.account->session().premium()
				|| d.account->session().isTestMode());
	});
	return std::min(int(premiumCount) + kMaxAccounts, kPremiumMaxAccounts);
}

rpl::producer<int> Domain::maxAccountsChanges() const {
	return _lastMaxAccounts.changes();
}

} // namespace Main
