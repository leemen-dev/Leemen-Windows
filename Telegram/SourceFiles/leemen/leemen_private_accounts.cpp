#include "leemen/leemen_private_accounts.h"

#include "base/weak_ptr.h"
#include "core/application.h"
#include "core/core_screenshot_protection.h"
#include "data/data_session.h"
#include "iv/editor/iv_editor_session.h"
#include "leemen/leemen_private_space.h"
#include "leemen/sync_service.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "media/player/media_player_instance.h"
#include "storage/storage_domain.h"
#include "storage/storage_account.h"
#include "window/notifications_manager.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include <crl/crl_async.h>
#include <crl/crl_on_main.h>
#include <openssl/crypto.h>
#include <QtCore/QDataStream>
#include <QtCore/QIODevice>
#include <QtCore/QPointer>
#include <QtGui/QGuiApplication>
#include <algorithm>
#include <limits>

namespace Leemen {
namespace {

bool Foreground() {
	return QGuiApplication::applicationState() == Qt::ApplicationActive
		&& !Core::App().passcodeLocked();
}

std::uint64_t Reject(Fn<void(bool)> done) {
	crl::on_main([done = std::move(done)] { if (done) done(false); });
	return 0;
}

void PinJob(QByteArray bytes, std::optional<LocalPin> existing, Fn<void(std::optional<LocalPin>)> done) {
	crl::async([bytes = std::make_unique<QByteArray>(std::move(bytes)), existing, done = std::move(done)]() mutable {
		const auto input = std::string_view(bytes->constData(), std::size_t(bytes->size()));
		const auto result = existing
			? (VerifyLocalPin(input, *existing) ? existing : std::nullopt)
			: CreateLocalPin(input);
		OPENSSL_cleanse(bytes->data(), std::size_t(bytes->size()));
		bytes.reset();
		crl::on_main([result, done = std::move(done)] { done(result); });
	});
}

} // namespace

AccountIdentity PrivateAccountIdentity(not_null<Main::Session*> session) {
	return { session->userId().bare, session->isTestMode() };
}

bool PrivateAccountContentAllowed(not_null<Main::Session*> session) {
	return session->domain().privateAccounts().contentAllowed(session);
}

bool PrivateAccountNotificationsAllowed(not_null<Main::Session*> session) {
	const auto &accounts = session->domain().privateAccounts();
	return !accounts.damaged() && !accounts.hidden(&session->account());
}

bool PrivateAccountVisibleFrom(not_null<Main::Account*> viewer, not_null<Main::Account*> target) {
	return viewer->domain().privateAccounts().visibleFrom(viewer, target);
}

PrivateAccounts::PrivateAccounts(not_null<Main::Domain*> domain) : _domain(domain) {
}

void PrivateAccounts::start() {
	if (_started) return;
	_started = true;
	Core::App().screenshotProtection().addContentReason(_screenProtected.value(), _lifetime);
	Core::App().appDeactivatedValue() | rpl::on_next([=](bool away) {
		if (away) lock();
	}, _lifetime);
	Core::App().passcodeLockValue() | rpl::on_next([=](bool locked) {
		if (locked) lock();
	}, _lifetime);
	_domain->activeValue() | rpl::on_next([=](Main::Account *account) {
		++_epoch;
		_operation = 0;
		if (_loginSlot && (!account || account->localIndex() != *_loginSlot)) {
			_loginSlot.reset();
			_screenProtected = false;
		}
		if (_grant && (!account || !account->maybeSession()
			|| PrivateAccountIdentity(&account->session()) != *_grant)) {
			_grant.reset();
			_returnTo.reset();
			closeHiddenWindows();
			_screenProtected = _loginSlot && account && account->localIndex() == *_loginSlot;
		}
		notify();
	}, _lifetime);
}

void PrivateAccounts::finish() {
	++_epoch;
	_operation = 0;
	_grant.reset();
	_returnTo.reset();
	_loginSlot.reset();
	_screenProtected = false;
	_lifetime.destroy();
	_started = false;
}

bool PrivateAccounts::restore(const QByteArray &bytes) {
	if (bytes.isEmpty()) {
		_state = {};
		_damaged = false;
		_damagedBytes.clear();
		_failedAttempts = 0;
		_blockedUntil = 0;
		return true;
	}
	_damaged = true;
	_damagedBytes = bytes;
	if (std::size_t(bytes.size()) > kMaxPrivateAccountsBytes + 16) return false;
	auto stream = QDataStream(bytes);
	stream.setVersion(QDataStream::Qt_5_1);
	auto version = qint32();
	auto attempts = qint32();
	auto graph = QByteArray();
	stream >> version >> attempts >> graph;
	if (version != 1 || attempts < 0 || attempts > 5
		|| stream.status() != QDataStream::Ok || !stream.atEnd()) return false;
	auto parsed = DecodePrivateAccounts({ reinterpret_cast<const unsigned char*>(graph.constData()), std::size_t(graph.size()) });
	if (!parsed) return false;
	_state = std::move(*parsed);
	_failedAttempts = attempts;
	_blockedUntil = attempts == 5 ? crl::now() + crl::time(30000) : 0;
	_damaged = false;
	_damagedBytes.clear();
	return true;
}

QByteArray PrivateAccounts::serialize() const {
	if (_damaged) return _damagedBytes;
	const auto graph = EncodePrivateAccounts(_state);
	auto result = QByteArray();
	auto stream = QDataStream(&result, QIODevice::WriteOnly);
	stream.setVersion(QDataStream::Qt_5_1);
	stream << qint32(1) << qint32(_failedAttempts)
		<< QByteArray(reinterpret_cast<const char*>(graph.data()), int(graph.size()));
	return result;
}

void PrivateAccounts::blockCorruptedStartup() {
	if (!_damaged) _damagedBytes = serialize();
	_damaged = true;
}

bool PrivateAccounts::damaged() const { return _damaged; }

bool PrivateAccounts::configured() const { return _damaged || !_state.snapshot().empty() || !_state.logins().empty(); }

bool PrivateAccounts::startupAllowed(const PrivateAccountSlots &accounts) {
	return !_damaged && _state.reconcileStartup(accounts);
}

bool PrivateAccounts::reserved(not_null<Main::Account*> account) const {
	return _state.logins().contains(std::uint32_t(account->localIndex()));
}

bool PrivateAccounts::loginCancelling(not_null<Main::Account*> account) const {
	const auto i = _state.logins().find(std::uint32_t(account->localIndex()));
	return i != _state.logins().end() && i->second.cancelling;
}

bool PrivateAccounts::pendingLogin(not_null<Main::Session*> owner, not_null<Main::Account*> account) const {
	const auto i = _state.logins().find(std::uint32_t(account->localIndex()));
	return i != _state.logins().end() && i->second.owner == PrivateAccountIdentity(owner)
		&& (!account->maybeSession() || i->second.cancelling || !i->second.completed);
}

bool PrivateAccounts::reserveLogin(not_null<Main::Session*> owner, not_null<Main::Account*> account) {
	if (!managementAllowed(owner) || !owner->leemen().active() || !PrivateSpace::EnrollmentEnabled()
		|| !owner->leemen().syncEnabled()
		|| owner->leemen().syncService().premium().access != Security::PremiumAccess::Active) return false;
	if (!_state.reserveLogin(std::uint32_t(account->localIndex()), PrivateAccountIdentity(owner), true)) return false;
	return true;
}

bool PrivateAccounts::persistNewLogin(not_null<Main::Account*> account) {
	if (!reserved(account) || account->maybeSession() || !account->local().writeMtpDataSync()
		|| !account->local().writeMtpConfigSync() || !persist()) {
		persistenceFailed();
		return false;
	}
	return true;
}

bool PrivateAccounts::beginLogin(not_null<Main::Session*> owner) {
	if (!managementAllowed(owner) || !owner->leemen().active()) return false;
	const auto account = _domain->addHidden(owner);
	return account && resumeLogin(owner, account);
}

bool PrivateAccounts::resumeLogin(not_null<Main::Session*> owner, not_null<Main::Account*> account) {
	if (!managementAllowed(owner) || !owner->leemen().active() || !pendingLogin(owner, account)
		|| account->maybeSession() || account->loggingOut()) return false;
	const auto &login = _state.logins().at(std::uint32_t(account->localIndex()));
	if (login.cancelling) return false;
	_loginSlot = account->localIndex();
	_screenProtected = true;
	_domain->activate(account);
	return true;
}

void PrivateAccounts::returnFromLogin(AccountIdentity owner) {
	_loginSlot.reset();
	if (const auto safe = safeAccount(accountFor(owner))) _domain->activate(safe);
	closeHiddenWindows();
	_screenProtected = false;
	notify();
}

bool PrivateAccounts::cancelLogin(not_null<Main::Session*> owner, not_null<Main::Account*> account) {
	if (!managementAllowed(owner) || !pendingLogin(owner, account)) return false;
	_state.cancelLogin(std::uint32_t(account->localIndex()));
	if (!persist()) { persistenceFailed(); return false; }
	const auto ownerId = PrivateAccountIdentity(owner);
	const auto weakAccount = base::make_weak(account);
	returnFromLogin(ownerId);
	if (weakAccount) weakAccount->logOut();
	return true;
}

bool PrivateAccounts::redirectDuplicateLogin(not_null<Main::Account*> account) {
	const auto i = _state.logins().find(std::uint32_t(account->localIndex()));
	if (i == _state.logins().end()) return false;
	const auto owner = i->second.owner;
	_state.cancelLogin(i->first);
	if (!persist()) { persistenceFailed(); return true; }
	const auto guard = QPointer<PrivateAccounts>(this);
	const auto weakAccount = base::make_weak(account);
	crl::on_main(account, [=] {
		if (!guard) return;
		guard->returnFromLogin(owner);
		if (weakAccount) weakAccount->logOut();
	});
	return true;
}

void PrivateAccounts::completeLogin(not_null<Main::Account*> account, not_null<Main::Session*> session) {
	const auto slot = std::uint32_t(account->localIndex());
	const auto i = _state.logins().find(slot);
	if (i == _state.logins().end()) return;
	const auto login = i->second;
	const auto id = PrivateAccountIdentity(session);
	const auto changed = !login.completed;
	const auto completed = !login.cancelling && _state.completeLogin(slot, id);
	if (!login.cancelling && !completed) {
		if (login.completed) {
			blockCorruptedStartup();
		} else {
			_state.cancelLogin(slot);
			if (!persist()) blockCorruptedStartup();
		}
	} else if (completed && changed && !persist()) {
		blockCorruptedStartup();
	}
	const auto guard = QPointer<PrivateAccounts>(this);
	const auto weak = base::make_weak(session);
	crl::on_main(account, [=] {
		if (!guard || !weak || account->maybeSession() != weak.get()) return;
		if (guard->_damaged) { guard->persistenceFailed(); return; }
		const auto current = guard->_state.logins().find(slot);
		if (current == guard->_state.logins().end()) return;
		const auto cancelling = current->second.cancelling;
		if (guard->_loginSlot == int(slot)) guard->returnFromLogin(login.owner);
		if (weak && (cancelling || !guard->accountFor(login.owner))) account->logOut();
	});
}

void PrivateAccounts::loginLoggedOut(not_null<Main::Account*> account) {
	if (!reserved(account)) return;
	_state.cancelLogin(std::uint32_t(account->localIndex()));
	if (!persist() || !account->local().writeMtpDataSync()) { persistenceFailed(); return; }
	const auto guard = QPointer<PrivateAccounts>(this);
	crl::on_main(account, [=] {
		if (!guard || account->maybeSession() || account->loggingOut()) return;
		guard->lock();
		if (!guard->_domain->removePrivateLogin(account)) guard->persistenceFailed();
	});
}

bool PrivateAccounts::releaseRemovedLogin(int slot) {
	const auto i = _state.logins().find(std::uint32_t(slot));
	if (i == _state.logins().end()) return false;
	const auto previous = _state;
	const auto completed = i->second.completed;
	_state.releaseLogin(std::uint32_t(slot));
	if (completed) {
		auto snapshot = _state.snapshot();
		for (auto j = snapshot.begin(); j != snapshot.end();) {
			j->second.hidden.erase(*completed);
			if (j->first == *completed) j->second.switchPin.reset();
			if (j->second.hidden.empty() && !j->second.switchPin) j = snapshot.erase(j);
			else ++j;
		}
		Expects(_state.restore(std::move(snapshot)));
	}
	if (!persist()) { _state = previous; persistenceFailed(); return false; }
	return true;
}

bool PrivateAccounts::hidden(not_null<Main::Account*> account) const {
	const auto session = account->maybeSession();
	return reserved(account) || (session && (_damaged || _state.isHiddenByAny(PrivateAccountIdentity(session))));
}

int PrivateAccounts::hiddenCount(not_null<Main::Session*> owner) const {
	const auto i = _state.snapshot().find(PrivateAccountIdentity(owner));
	const auto id = PrivateAccountIdentity(owner);
	return (i == _state.snapshot().end() ? 0 : int(i->second.hidden.size()))
		+ int(std::count_if(_state.logins().begin(), _state.logins().end(), [&](const auto &entry) {
			return entry.second.owner == id && !entry.second.completed;
		}));
}

int PrivateAccounts::unavailableHiddenCount(not_null<Main::Session*> owner) const {
	const auto i = _state.snapshot().find(PrivateAccountIdentity(owner));
	return i == _state.snapshot().end() ? 0 : int(std::count_if(
		i->second.hidden.begin(), i->second.hidden.end(), [&](AccountIdentity id) { return !accountFor(id); }));
}

bool PrivateAccounts::hiddenBy(not_null<Main::Session*> owner, not_null<Main::Account*> target) const {
	const auto session = target->maybeSession();
	return session && _state.isHiddenBy(PrivateAccountIdentity(owner), PrivateAccountIdentity(session));
}

bool PrivateAccounts::visibleFrom(not_null<Main::Account*> viewer, not_null<Main::Account*> target) const {
	const auto targetSession = target->maybeSession();
	if (reserved(target) && !targetSession) return false;
	if (!targetSession) return true;
	if (_damaged || _state.loginBlocks(std::uint32_t(target->localIndex()), PrivateAccountIdentity(targetSession))) return false;
	const auto viewerSession = viewer->maybeSession();
	return viewerSession
		? !_state.hiddenFrom(PrivateAccountIdentity(viewerSession), PrivateAccountIdentity(targetSession), viewerSession->leemen().active())
		: !_state.isHiddenByAny(PrivateAccountIdentity(targetSession));
}

bool PrivateAccounts::contentAllowed(not_null<Main::Session*> session) const {
	if (_damaged) return false;
	const auto id = PrivateAccountIdentity(session);
	if (_state.loginBlocks(std::uint32_t(session->account().localIndex()), id)) return false;
	return !_state.isHiddenByAny(id) || (_grant == id
		&& _domain->maybeActive() == &session->account() && Foreground());
}

bool PrivateAccounts::canActivate(not_null<Main::Account*> account) const {
	if (reserved(account) && !account->maybeSession()) {
		return !_damaged && _loginSlot == account->localIndex() && Foreground();
	}
	if (const auto session = account->maybeSession(); session
		&& _state.loginBlocks(std::uint32_t(account->localIndex()), PrivateAccountIdentity(session))) return false;
	return !account->maybeSession() || (!_damaged && (!hidden(account)
		|| (_grant == PrivateAccountIdentity(&account->session()) && Foreground())));
}

Main::Account *PrivateAccounts::accountAt(int slot) const {
	for (const auto &[index, account] : _domain->accounts()) if (index == slot) return account.get();
	return nullptr;
}

Main::Account *PrivateAccounts::accountFor(AccountIdentity identity) const {
	for (const auto &[index, account] : _domain->accounts()) {
		if (const auto session = account->maybeSession(); session && PrivateAccountIdentity(session) == identity) return account.get();
	}
	return nullptr;
}

Main::Account *PrivateAccounts::safeAccount(Main::Account *preferred) const {
	if (_damaged) return nullptr;
	auto available = std::vector<AccountIdentity>();
	for (const auto &[index, account] : _domain->accounts()) {
		if (const auto session = account->maybeSession(); session && !hidden(account.get())) {
			available.push_back(PrivateAccountIdentity(session));
		}
	}
	const auto preferredId = preferred && preferred->maybeSession()
		? std::make_optional(PrivateAccountIdentity(&preferred->session())) : std::nullopt;
	const auto result = _state.safeAccount(available, preferredId);
	if (result) return accountFor(*result);
	for (const auto &[index, account] : _domain->accounts()) {
		if (!account->maybeSession() && !reserved(account.get())) return account.get();
	}
	return nullptr;
}

bool PrivateAccounts::hasSwitchPin(not_null<Main::Session*> owner) const {
	return _state.switchPin(PrivateAccountIdentity(owner)) != nullptr;
}

int PrivateAccounts::retryAfterSeconds() const {
	return int(std::max(crl::time(0), _blockedUntil - crl::now() + 999) / 1000);
}

rpl::producer<> PrivateAccounts::changes() const { return _changes.events(); }

bool PrivateAccounts::managementAllowed(not_null<Main::Session*> owner) const {
	return !_damaged && _domain->maybeActive() == &owner->account()
		&& Foreground() && owner->leemen().managementAllowed();
}

bool PrivateAccounts::persist() {
	return _domain->started() && _domain->local().writePrivateAccountsSync(serialize());
}

void PrivateAccounts::persistenceFailed() {
	blockCorruptedStartup();
	lock();
	Core::App().lockByPasscode();
}

void PrivateAccounts::notify() {
	if (!_started || _notifying) return;
	_notifying = true;
	auto sessions = std::vector<base::weak_ptr<Main::Session>>();
	for (const auto &[index, account] : _domain->accounts()) {
		if (const auto session = account->maybeSession()) sessions.push_back(base::make_weak(session));
	}
	for (const auto &session : sessions) {
		if (session) session->leemen().accountVisibilityChanged();
	}
	_changes.fire({});
	if (_domain->started()) _domain->notifyUnreadBadgeChanged();
	_notifying = false;
}

bool PrivateAccounts::setHidden(not_null<Main::Session*> owner, not_null<Main::Account*> target, bool hide) {
	if (!managementAllowed(owner) || !target->maybeSession()
		|| (hide && (!PrivateSpace::EnrollmentEnabled() || !owner->leemen().active()))) return false;
	const auto premium = owner->leemen().syncEnabled()
		&& owner->leemen().syncService().premium().access == Security::PremiumAccess::Active;
	const auto previous = _state;
	const auto result = _state.setHidden(PrivateAccountIdentity(owner), PrivateAccountIdentity(&target->session()), hide, premium);
	if (result == HideAccountResult::Unchanged) return true;
	if (result != HideAccountResult::Changed) return false;
	if (!persist()) {
		if (!hide) _state = previous;
		persistenceFailed();
		return false;
	}
	++_epoch;
	_operation = 0;
	if (hide) {
		auto windows = std::vector<base::weak_ptr<Window::Controller>>();
		for (const auto window : Core::App().windowStack()) windows.push_back(base::make_weak(window));
		for (const auto &window : windows) {
			if (window) window->hideSettingsAndLayer(anim::type::instant);
		}
	}
	closeHiddenWindows();
	notify();
	return true;
}

bool PrivateAccounts::revealUnavailable(not_null<Main::Session*> owner) {
	if (!managementAllowed(owner)) return false;
	const auto previous = _state;
	const auto id = PrivateAccountIdentity(owner);
	const auto i = previous.snapshot().find(id);
	if (i == previous.snapshot().end()) return true;
	for (const auto child : i->second.hidden) {
		if (!accountFor(child)) {
			Expects(_state.setHidden(id, child, false, false) == HideAccountResult::Changed);
		}
	}
	if (!persist()) {
		_state = previous;
		persistenceFailed();
		return false;
	}
	++_epoch;
	_operation = 0;
	notify();
	return true;
}

std::uint64_t PrivateAccounts::activateWithPin(not_null<Main::Account*> target, const QString &pin, Fn<void(bool)> done) {
	if (_damaged || !_domain->maybeActive() || !Foreground() || _operation || pin.size() > 12
		|| !target->maybeSession() || !_domain->active().maybeSession()
		|| _nextOperation == std::numeric_limits<std::uint64_t>::max()) return Reject(std::move(done));
	const auto owner = &_domain->active().session();
	const auto ownerId = PrivateAccountIdentity(owner);
	const auto targetId = PrivateAccountIdentity(&target->session());
	if (_state.loginBlocks(std::uint32_t(target->localIndex()), targetId)) return Reject(std::move(done));
	if (!owner->leemen().active() || !_state.isHiddenBy(ownerId, targetId)
		|| retryAfterSeconds()) return Reject(std::move(done));
	const auto existing = _state.switchPin(ownerId);
	const auto request = _operation = ++_nextOperation;
	const auto before = _epoch;
	const auto guard = QPointer<PrivateAccounts>(this);
	auto complete = [=, done = std::move(done)](bool success) mutable {
		if (!guard || guard->_epoch != before || guard->_operation != request || !Foreground()) {
			done(false);
			return;
		}
		guard->_operation = 0;
		const auto ownerAccount = guard->accountFor(ownerId);
		const auto targetAccount = guard->accountFor(targetId);
		if (!ownerAccount || !targetAccount || &guard->_domain->active() != ownerAccount
			|| !ownerAccount->session().leemen().active() || !guard->_state.isHiddenBy(ownerId, targetId)) {
			done(false);
			return;
		}
		if (!success) {
			guard->_failedAttempts = std::min(guard->_failedAttempts + 1, 5);
			if (guard->_failedAttempts == 5) guard->_blockedUntil = crl::now() + crl::time(30000);
			if (!guard->persist()) guard->persistenceFailed();
			done(false);
			return;
		}
		guard->_failedAttempts = 0;
		guard->_blockedUntil = 0;
		if (!guard->persist()) {
			guard->persistenceFailed();
			done(false);
			return;
		}
		guard->_grant = targetId;
		guard->_returnTo = ownerId;
		guard->_screenProtected = true;
		if (guard->_grant != targetId || !Foreground()) {
			done(false);
			return;
		}
		guard->_domain->activate(targetAccount);
		done(true);
	};
	if (existing) {
		PinJob(pin.toUtf8(), *existing, [complete = std::move(complete)](std::optional<LocalPin> value) mutable {
			complete(value.has_value());
		});
	} else {
		crl::on_main([complete = std::move(complete)]() mutable { complete(true); });
	}
	return request;
}

std::uint64_t PrivateAccounts::setSwitchPin(not_null<Main::Session*> owner, const QString &pin, Fn<void(bool)> done) {
	if (!managementAllowed(owner) || _operation || pin.size() > 12
		|| _nextOperation == std::numeric_limits<std::uint64_t>::max()) return Reject(std::move(done));
	const auto id = PrivateAccountIdentity(owner);
	const auto request = _operation = ++_nextOperation;
	const auto before = _epoch;
	const auto guard = QPointer<PrivateAccounts>(this);
	const auto clear = pin.isEmpty();
	auto complete = [=, done = std::move(done)](std::optional<LocalPin> value) mutable {
		if (!guard || guard->_epoch != before || guard->_operation != request) {
			done(false);
			return;
		}
		guard->_operation = 0;
		const auto account = guard->accountFor(id);
		if (!account || !guard->managementAllowed(&account->session()) || (!clear && !value)) {
			done(false);
			return;
		}
		const auto previous = guard->_state;
		const auto changed = guard->_state.setSwitchPin(id, std::move(value));
		const auto success = changed && guard->persist();
		if (!success) {
			guard->_state = previous;
			if (changed) guard->persistenceFailed();
		}
		++guard->_epoch;
		guard->notify();
		done(success);
	};
	if (clear) crl::on_main([complete = std::move(complete)]() mutable { complete(std::nullopt); });
	else PinJob(pin.toUtf8(), std::nullopt, std::move(complete));
	return request;
}

void PrivateAccounts::cancelOperation(std::uint64_t request) {
	if (request && request == _operation) { _operation = 0; ++_epoch; }
}

void PrivateAccounts::watchAccount(not_null<Main::Account*> account) {
	const auto identity = std::make_shared<std::optional<AccountIdentity>>();
	account->sessionValue() | rpl::on_next([=](Main::Session *session) {
		if (!_started) return;
		if (!session) {
			if (*identity && !Core::Quitting()) loggedOut(**identity);
			identity->reset();
			const auto i = _state.logins().find(std::uint32_t(account->localIndex()));
			if (i != _state.logins().end() && i->second.cancelling && !account->loggingOut()) {
				const auto guard = QPointer<PrivateAccounts>(this);
				crl::on_main(account, [=] {
					if (guard && guard->loginCancelling(account) && !account->loggingOut()) account->logOut();
				});
			}
			return;
		}
		*identity = PrivateAccountIdentity(session);
		session->leemen().changes() | rpl::on_next([=] { notify(); }, session->lifetime());
		if (reserved(account)) {
			const auto guard = QPointer<PrivateAccounts>(this);
			const auto weak = base::make_weak(session);
			crl::on_main(account, [=] { if (guard && weak && !guard->contentAllowed(weak.get())) guard->lock(); });
		} else if (!contentAllowed(session)) lock();
	}, account->lifetime());
}

void PrivateAccounts::loggedOut(AccountIdentity account) {
	++_epoch;
	_operation = 0;
	if (_state.snapshot().empty() && _state.logins().empty()) return;
	const auto children = _state.logoutClosure(account);
	const auto previous = _state;
	auto pending = std::vector<int>();
	auto bound = false;
	for (const auto &[slot, login] : _state.logins()) {
		bound = bound || login.completed == account;
		if (login.owner == account || login.completed == account
			|| std::ranges::find(children, login.owner) != children.end()) {
			_state.cancelLogin(slot);
			pending.push_back(int(slot));
		}
	}
	auto snapshot = _state.snapshot();
	for (auto i = snapshot.begin(); i != snapshot.end();) {
		if (!bound) i->second.hidden.erase(account);
		if (i->first == account) i->second.switchPin.reset();
		if (i->second.hidden.empty() && !i->second.switchPin) i = snapshot.erase(i);
		else ++i;
	}
	Expects(_state.restore(std::move(snapshot)));
	if (!persist()) {
		_state = previous;
		persistenceFailed();
		return;
	}
	for (const auto child : children) {
		if (const auto target = accountFor(child); target && !target->loggingOut()) target->logOut();
	}
	for (const auto slot : pending) {
		if (const auto target = accountAt(slot); target && !target->loggingOut()
			&& (!target->maybeSession() || PrivateAccountIdentity(&target->session()) != account)) target->logOut();
	}
	lock();
}

void PrivateAccounts::closeHiddenWindows() {
	auto windows = std::vector<base::weak_ptr<Window::Controller>>();
	for (const auto window : Core::App().windowStack()) windows.push_back(base::make_weak(window));
	for (const auto &weak : windows) {
		auto window = weak.get();
		if (!window) continue;
		const auto session = window->maybeSession();
		if (!session || !hidden(&session->account())) continue;
		Core::App().notifications().clearFromSession(session);
		window = weak.get();
		if (!window || window->maybeSession() != session) continue;
		if (!contentAllowed(session)) {
			Iv::Editor::CloseWindowsForSession(session);
			window = weak.get();
			if (!window || window->maybeSession() != session) continue;
			window->hideSettingsAndLayer(anim::type::instant);
			window = weak.get();
			if (!window || window->maybeSession() != session) continue;
			window->widget()->hide();
			window = weak.get();
			if (!window || window->maybeSession() != session) continue;
			if (!window->isPrimary()) Core::App().closeWindow(window);
			else if (!Core::App().closeNonLastAsync(window)) continue;
		}
	}
}

void PrivateAccounts::lock() {
	if (_locking) return;
	_locking = true;
	++_epoch;
	_operation = 0;
	_grant.reset();
	auto fallback = _returnTo ? accountFor(*_returnTo) : nullptr;
	if (_loginSlot) {
		const auto i = _state.logins().find(std::uint32_t(*_loginSlot));
		if (i != _state.logins().end()) fallback = accountFor(i->second.owner);
	}
	_loginSlot.reset();
	_returnTo.reset();
	if (_domain->maybeActive() && hidden(_domain->maybeActive())) {
		Core::App().hideMediaView();
		Media::Player::instance()->stopAndClose();
		if (const auto safe = safeAccount(fallback)) _domain->activate(safe);
	}
	closeHiddenWindows();
	_screenProtected = false;
	_locking = false;
	notify();
}

} // namespace Leemen
