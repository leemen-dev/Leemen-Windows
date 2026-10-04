#pragma once

#include "leemen/private_accounts_state.h"

#include <QtCore/QByteArray>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <crl/crl_time.h>
#include <rpl/event_stream.h>
#include <rpl/lifetime.h>
#include <rpl/variable.h>

namespace Main {
class Account;
class Domain;
class Session;
} // namespace Main

namespace Leemen {

class PrivateAccounts final : public QObject {
public:
	explicit PrivateAccounts(not_null<Main::Domain*> domain);
	void start();
	void finish();
	bool restore(const QByteArray &bytes);
	void blockCorruptedStartup();
	[[nodiscard]] QByteArray serialize() const;
	[[nodiscard]] bool damaged() const;
	[[nodiscard]] bool configured() const;
	[[nodiscard]] bool startupAllowed(const PrivateAccountSlots &accounts);
	[[nodiscard]] bool reserved(not_null<Main::Account*> account) const;
	[[nodiscard]] bool loginCancelling(not_null<Main::Account*> account) const;
	[[nodiscard]] bool pendingLogin(not_null<Main::Session*> owner, not_null<Main::Account*> account) const;
	bool beginLogin(not_null<Main::Session*> owner);
	bool resumeLogin(not_null<Main::Session*> owner, not_null<Main::Account*> account);
	bool cancelLogin(not_null<Main::Session*> owner, not_null<Main::Account*> account);
	bool reserveLogin(not_null<Main::Session*> owner, not_null<Main::Account*> account);
	bool persistNewLogin(not_null<Main::Account*> account);
	void completeLogin(not_null<Main::Account*> account, not_null<Main::Session*> session);
	void loginLoggedOut(not_null<Main::Account*> account);
	bool redirectDuplicateLogin(not_null<Main::Account*> account);
	bool releaseRemovedLogin(int slot);
	[[nodiscard]] bool hidden(not_null<Main::Account*> account) const;
	[[nodiscard]] int hiddenCount(not_null<Main::Session*> owner) const;
	[[nodiscard]] int unavailableHiddenCount(not_null<Main::Session*> owner) const;
	[[nodiscard]] bool hiddenBy(not_null<Main::Session*> owner, not_null<Main::Account*> target) const;
	[[nodiscard]] bool visibleFrom(not_null<Main::Account*> viewer, not_null<Main::Account*> target) const;
	[[nodiscard]] bool contentAllowed(not_null<Main::Session*> session) const;
	[[nodiscard]] bool canActivate(not_null<Main::Account*> account) const;
	[[nodiscard]] Main::Account *safeAccount(Main::Account *preferred = nullptr) const;
	[[nodiscard]] bool hasSwitchPin(not_null<Main::Session*> owner) const;
	[[nodiscard]] int retryAfterSeconds() const;
	[[nodiscard]] rpl::producer<> changes() const;
	bool setHidden(not_null<Main::Session*> owner, not_null<Main::Account*> target, bool hidden);
	bool revealUnavailable(not_null<Main::Session*> owner);
	std::uint64_t activateWithPin(not_null<Main::Account*> target, const QString &pin, Fn<void(bool)> done);
	std::uint64_t setSwitchPin(not_null<Main::Session*> owner, const QString &pin, Fn<void(bool)> done);
	void cancelOperation(std::uint64_t request);
	void watchAccount(not_null<Main::Account*> account);
	void lock();

private:
	[[nodiscard]] bool managementAllowed(not_null<Main::Session*> owner) const;
	[[nodiscard]] Main::Account *accountFor(AccountIdentity identity) const;
	[[nodiscard]] Main::Account *accountAt(int slot) const;
	void returnFromLogin(AccountIdentity owner);
	bool persist();
	void persistenceFailed();
	void notify();
	void closeHiddenWindows();
	void loggedOut(AccountIdentity account);

	const not_null<Main::Domain*> _domain;
	PrivateAccountsState _state;
	QByteArray _damagedBytes;
	bool _damaged = false;
	bool _started = false;
	bool _locking = false;
	bool _notifying = false;
	std::optional<AccountIdentity> _grant;
	std::optional<AccountIdentity> _returnTo;
	std::optional<int> _loginSlot;
	std::uint64_t _epoch = 0;
	std::uint64_t _operation = 0;
	std::uint64_t _nextOperation = 0;
	int _failedAttempts = 0;
	crl::time _blockedUntil = 0;
	rpl::event_stream<> _changes;
	rpl::variable<bool> _screenProtected = false;
	rpl::lifetime _lifetime;
};

[[nodiscard]] AccountIdentity PrivateAccountIdentity(not_null<Main::Session*> session);
[[nodiscard]] bool PrivateAccountContentAllowed(not_null<Main::Session*> session);
[[nodiscard]] bool PrivateAccountNotificationsAllowed(not_null<Main::Session*> session);
[[nodiscard]] bool PrivateAccountVisibleFrom(not_null<Main::Account*> viewer, not_null<Main::Account*> target);

} // namespace Leemen
