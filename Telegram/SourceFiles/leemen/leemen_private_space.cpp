#include "leemen/leemen_private_space.h"

#include "leemen/sync_peer_id.h"
#include "leemen/sync_service.h"
#include "leemen/leemen_private_accounts.h"
#include "base/weak_ptr.h"

#include "core/application.h"
#include "core/core_screenshot_protection.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "dialogs/dialogs_indexed_list.h"
#include "history/history.h"
#include "iv/editor/iv_editor_session.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "main/main_session_settings.h"
#include "storage/storage_account.h"
#include "media/player/media_player_instance.h"
#include "window/notifications_manager.h"
#include "window/window_session_controller.h"

#include <crl/crl_async.h>
#include <crl/crl_on_main.h>
#include <openssl/crypto.h>
#include <QtCore/QDataStream>
#include <QtCore/QIODevice>
#include <QtGui/QGuiApplication>

namespace Leemen {
namespace {

constexpr auto kVersion = qint32(3);
constexpr auto kMaximumPeers = 100000;
constexpr auto kRetryDelay = crl::time(30000);

bool ServicePeer(PeerId peer) {
	return peer == PeerId(UserId(333000))
		|| peer == PeerId(UserId(777000));
}

std::uint64_t RejectPinOperation(Fn<void(bool)> done) {
	crl::on_main([done = std::move(done)] { done(false); });
	return 0;
}

void RunPinJob(
		QByteArray bytes,
		std::optional<LocalPin> verifier,
		Fn<void(std::optional<LocalPin>)> done) {
	crl::async([
		bytes = std::make_unique<QByteArray>(std::move(bytes)),
		verifier,
		done = std::move(done)
	] () mutable {
		const auto text = std::string_view(bytes->constData(), bytes->size());
		const auto result = verifier
			? (VerifyLocalPin(text, *verifier) ? verifier : std::nullopt)
			: CreateLocalPin(text);
		OPENSSL_cleanse(bytes->data(), bytes->size());
		bytes.reset();
		crl::on_main([result, done = std::move(done)] { done(result); });
	});
}

} // namespace

PrivateSpace::PrivateSpace(not_null<Main::Session*> session)
: _session(session) {
	_syncEnabled = !session->settings().leemenSync().isEmpty();
	if (session->settings().sessionSettingsReadFailed()) {
		_damaged = true;
	} else {
		read(session->settings().leemenPrivateSpace());
	}
}

PrivateSpace::~PrivateSpace() = default;

void PrivateSpace::accountVisibilityChanged() {
	if (!_started) {
		return;
	}
	const auto allowed = PrivateAccountContentAllowed(_session);
	if (_accountContentAllowed == allowed) {
		if (active() && requiresLimitResolution()) {
			transition([&] { _state.setActive(false); });
		} else {
			_session->data().notifyUnreadBadgeChanged();
			_changes.fire({});
		}
		return;
	}
	_accountContentAllowed = allowed;
	const auto weak = base::make_weak(_session.get());
	if (!allowed) {
		_pinWindow.clear();
		cancelPinOperation(_pendingPinRequest);
	}
	transition([&] {
		if (!allowed) {
			_managementAuthorized = false;
			_state.setActive(false);
		} else if (active() && requiresLimitResolution()) {
			_state.setActive(false);
		}
	}, 0, true);
	if (weak && !allowed && _sync && _sync->maxMode() && !_syncApplying) {
		_sync->lockMax();
	}
}

void PrivateSpace::start() {
	_started = true;
	initPrivateMessages();
	if (_syncEnabled && !_damaged) {
		startSync();
	}
	Core::App().screenshotProtection().addContentReason(
		_changes.events_starting_with({}) | rpl::map([=] {
			return (active() || _managementAuthorized) && !_allowScreenshots;
		}),
		_lifetime);
	Core::App().appDeactivatedValue() | rpl::on_next([=](bool away) {
		if (away) {
			lock();
		}
	}, _lifetime);
	Core::App().passcodeLockValue() | rpl::on_next([=](bool locked) {
		if (locked) {
			lock(true);
		}
	}, _lifetime);
	_session->domain().activeValue(
	) | rpl::on_next([=](Main::Account *account) {
		if (account != &_session->account()) {
			lock(true);
		}
	}, _lifetime);
}

bool PrivateSpace::EnrollmentEnabled() {
#ifdef TDESKTOP_ENABLE_LEEMEN_PRIVATE_SPACE
	return true;
#else
	return false;
#endif // TDESKTOP_ENABLE_LEEMEN_PRIVATE_SPACE
}

bool PrivateSpace::configured() const {
	return _pin.has_value() || _damaged || _syncEnabled;
}

bool PrivateSpace::damaged() const {
	return _damaged;
}

bool PrivateSpace::active() const {
	return !_damaged && (!_syncEnabled || _syncTrusted) && _state.active();
}

bool PrivateSpace::hidden(PeerId peer) const {
	const auto direct = [&](PeerId id) {
		const auto canonical = Sync::CanonicalPeerId(id);
		return _state.hidden(id.value)
			|| (canonical && _syncHidden.contains(*canonical));
	};
	if (!peer || ServicePeer(peer)) {
		return false;
	} else if (_damaged || (_syncEnabled && !_syncTrusted && !_syncCachedMembership)
		|| direct(peer)) {
		return true;
	}
	if (_started) {
		if (const auto loaded = _session->data().peerLoaded(peer)) {
			if (const auto from = loaded->migrateFrom()) {
				if (direct(from->id)) {
					return true;
				}
			}
			if (const auto to = loaded->migrateTo()) {
				return direct(to->id);
			}
		}
	}
	return false;
}

bool PrivateSpace::allowsPeer(PeerId peer) const {
	return PrivateAccountContentAllowed(_session) && (active() || !hidden(peer));
}

bool PrivateSpace::canHide(PeerId peer) const {
	if (!peer || ServicePeer(peer) || peer == _session->userPeerId()) {
		return false;
	}
	const auto loaded = _session->data().peerLoaded(peer);
	return loaded && !loaded->isServiceUser();
}

int PrivateSpace::retryAfterSeconds() const {
	return int(std::max(crl::time(0), _blockedUntil - crl::now() + 999) / 1000);
}

int PrivateSpace::pinTimeoutMinutes() const {
	return _pinTimeoutMinutes;
}

bool PrivateSpace::screenshotsAllowed() const {
	return _allowScreenshots;
}

bool PrivateSpace::setPinTimeoutMinutes(int minutes) {
	if (!active() || minutes < 0) {
		return false;
	}
	if (_syncEnabled) {
		return syncMutate([=](auto &, auto &content, std::int64_t clock) {
			const auto unknown = content.settings.pinTimeoutMinutes
				? content.settings.pinTimeoutMinutes->unknownFields
				: Sync::UnknownFields();
			content.settings.pinTimeoutMinutes = Sync::IntRegister{
				minutes, clock, _syncDevice.toStdString(), unknown };
		});
	}
	_pinTimeoutMinutes = minutes;
	_pinWindow.setTimeout(std::chrono::minutes(minutes));
	const auto weak = base::make_weak(_session.get());
	save();
	if (!weak || _damaged) {
		return false;
	}
	_changes.fire({});
	return bool(weak);
}

bool PrivateSpace::setScreenshotsAllowed(bool allowed) {
	if (!active()) {
		return false;
	}
	if (_syncEnabled) {
		return syncMutate([=](auto &, auto &content, std::int64_t clock) {
			const auto unknown = content.settings.allowScreenshots
				? content.settings.allowScreenshots->unknownFields
				: Sync::UnknownFields();
			content.settings.allowScreenshots = Sync::BoolRegister{
				allowed, clock, _syncDevice.toStdString(), unknown };
		});
	}
	_allowScreenshots = allowed;
	const auto weak = base::make_weak(_session.get());
	save();
	if (!weak || _damaged) {
		return false;
	}
	_changes.fire({});
	return bool(weak);
}

bool PrivateSpace::onboardingCompleted() const {
	return _session->settings().leemenOnboardingCompleted();
}

bool PrivateSpace::completeOnboarding() {
	if (!active() || !managementAllowed() || !pinOperationAllowed()) {
		return false;
	}
	auto &settings = _session->settings();
	if (settings.leemenOnboardingCompleted()) {
		return true;
	}
	const auto weak = base::make_weak(_session.get());
	settings.setLeemenOnboardingCompleted(true);
	const auto written = _session->local().writeLeemenSettingsSync();
	if (!weak) {
		return false;
	}
	if (!written) {
		settings.setLeemenOnboardingCompleted(false);
	}
	return written;
}

bool PrivateSpace::unlockWithinGrace() {
	if (active() || !configured() || !pinOperationAllowed()
		|| _pendingPinRequest || !_pinWindow.skippable()) {
		return false;
	}
	const auto weak = base::make_weak(_session.get());
	transition([&] {
		_managementAuthorized = true;
		_state.setActive(!requiresLimitResolution());
	});
	return weak && managementAllowed();
}

rpl::producer<> PrivateSpace::changes() const {
	return _changes.events();
}

bool PrivateSpace::pinOperationAllowed() const {
	return !_damaged
		&& PrivateAccountContentAllowed(_session)
		&& (!_syncEnabled || (_sync && _sync->projection()))
		&& _session->account().maybeSession() == _session.get()
		&& _session->domain().started()
		&& &_session->domain().active() == &_session->account()
		&& QGuiApplication::applicationState() == Qt::ApplicationActive
		&& !Core::App().passcodeLocked();
}

std::uint64_t PrivateSpace::setPin(const QString &pin, Fn<void(bool)> done) {
	if (_syncEnabled) {
		return syncSetPin(pin, std::move(done));
	}
	if (!pinOperationAllowed()
		|| _pendingPinRequest
		|| (configured() ? !active() : !EnrollmentEnabled())) {
		return RejectPinOperation(std::move(done));
	}
	const auto enrolled = configured();
	const auto request = _pendingPinRequest = ++_pinGeneration;
	RunPinJob(
		pin.toUtf8(),
		std::nullopt,
		crl::guard(_session, [=](std::optional<LocalPin> replacement) {
			finishPinCreation(request, enrolled, replacement, done);
		}));
	return request;
}

std::uint64_t PrivateSpace::unlock(const QString &pin, Fn<void(bool)> done) {
	if (_syncEnabled && _syncProjection && _syncProjection->content.pin
		&& _syncProjection->content.pin->state == "set") {
		return syncUnlock(pin, std::move(done));
	}
	if (!pinOperationAllowed()
		|| !_pin
		|| _pendingPinRequest
		|| retryAfterSeconds()) {
		return RejectPinOperation(std::move(done));
	}
	const auto request = _pendingPinRequest = ++_pinGeneration;
	RunPinJob(
		pin.toUtf8(),
		_pin,
		crl::guard(_session, [=](std::optional<LocalPin> verified) {
			finishPinVerification(request, verified.has_value(), done);
		}));
	return request;
}

void PrivateSpace::finishPinCreation(
		std::uint64_t request,
		bool enrolled,
		std::optional<LocalPin> replacement,
		Fn<void(bool)> done) {
	if (_pendingPinRequest != request || _pinGeneration != request) {
		done(false);
		return;
	}
	_pendingPinRequest = 0;
	if (!replacement
		|| !pinOperationAllowed()
		|| configured() != enrolled
		|| (enrolled ? !active() : !EnrollmentEnabled())) {
		done(false);
		return;
	}
	_pin = replacement;
	_pinWindow.clear();
	_failedAttempts = 0;
	_blockedUntil = 0;
	const auto weak = base::make_weak(_session.get());
	save();
	if (!weak || _damaged) {
		done(false);
		return;
	}
	_session->data().notifyUnreadBadgeChanged();
	if (weak) {
		_changes.fire({});
	}
	done(bool(weak));
}

void PrivateSpace::finishPinVerification(
		std::uint64_t request,
		bool verified,
		Fn<void(bool)> done) {
	if (_pendingPinRequest != request || _pinGeneration != request) {
		done(false);
		return;
	}
	if (!pinOperationAllowed() || (!_pin && !_syncEnabled)) {
		cancelPinOperation(request);
		done(false);
		return;
	}
	if (!verified) {
		cancelPinOperation(request);
		_pinWindow.clear();
		_failedAttempts = std::min(_failedAttempts + 1, 5);
		if (_failedAttempts == 5) {
			_blockedUntil = crl::now() + kRetryDelay;
		}
		save();
		done(false);
		return;
	}
	_failedAttempts = 0;
	_blockedUntil = 0;
	const auto weak = base::make_weak(_session.get());
	save();
	if (!weak || _damaged) {
		done(false);
		return;
	}
	if (_syncEnabled && syncImportLocal(request, done)) {
		return;
	}
	if (!weak || _damaged) {
		done(false);
		return;
	}
	cancelPinOperation(request);
	_pinWindow.recordVerified();
	transition([&] {
		_managementAuthorized = true;
		_state.setActive(!requiresLimitResolution());
	});
	done(bool(weak));
}

void PrivateSpace::cancelPinOperation(std::uint64_t request) {
	if (request && _pendingPinRequest == request) {
		_pendingPinRequest = 0;
		if (_syncImportUnlockRequest == request) {
			_syncImportUnlockRequest = 0;
		}
		++_pinGeneration;
	}
}

void PrivateSpace::lock(bool clearVerification) {
	const auto weak = base::make_weak(_session.get());
	if (clearVerification) {
		_pinWindow.clear();
	}
	cancelPinOperation(_pendingPinRequest);
	if (active() || _managementAuthorized) {
		transition([&] {
			_managementAuthorized = false;
			_state.setActive(false);
		});
	}
	if (weak && _sync && _sync->maxMode() && !_syncApplying) {
		_sync->lockMax();
	}
}

bool PrivateSpace::setHidden(PeerId peer, bool hide) {
	if (!managementAllowed() || hidden(peer) == hide
		|| (hide && (!active() || !canHide(peer) || !canAddHiddenChat(peer)))) {
		return false;
	}
	if (_syncEnabled) {
		return syncSetHidden(peer, hide);
	}
	const auto weak = base::make_weak(_session.get());
	transition([&] {
		_state.setHidden(peer.value, hide);
		if (!hide) {
			forgetPrivateMessages(peer);
			if (!weak || _damaged) {
				return;
			}
			for (const auto related : affectedPeers(peer)) {
				const auto loaded = _session->data().peerLoaded(peer);
				if (loaded && ((loaded->migrateFrom()
					&& loaded->migrateFrom()->id == related)
					|| (loaded->migrateTo()
						&& loaded->migrateTo()->id == related))) {
					_state.setHidden(related.value, false);
					forgetPrivateMessages(related);
					if (!weak || _damaged) {
						return;
					}
				}
			}
		}
		save();
	}, peer);
	return weak && !_damaged;
}

bool PrivateSpace::disable() {
	if (!managementAllowed()) {
		return false;
	}
	if (_syncEnabled) {
		return syncDisable();
	}
	const auto weak = base::make_weak(_session.get());
	cancelPinOperation(_pendingPinRequest);
	transition([&] {
		_state = PrivateSpaceState();
		_managementAuthorized = false;
		_pin.reset();
		_pinWindow.clear();
		_pinTimeoutMinutes = 0;
		_pinWindow.setTimeout({});
		_allowScreenshots = true;
		_failedAttempts = 0;
		_blockedUntil = 0;
		save();
	});
	return weak && !_damaged;
}

std::set<PeerId> PrivateSpace::affectedPeers(PeerId extra, bool allPeers) const {
	auto result = std::set<PeerId>();
	if ((_syncEnabled || allPeers) && _started) {
		_session->data().enumerateUsers([&](not_null<UserData*> user) {
			result.emplace(user->id);
		});
		_session->data().enumerateGroups([&](not_null<PeerData*> group) {
			result.emplace(group->id);
		});
		_session->data().enumerateBroadcasts([&](not_null<ChannelData*> channel) {
			result.emplace(channel->id);
		});
	}
	for (const auto id : _syncHidden) {
		const auto bare = (id < 0) ? -id : id;
		if (std::uint64_t(bare) > PeerId::kChatTypeMask) {
			continue;
		} else if (id < 0) {
			result.emplace(ChatId(bare));
			result.emplace(ChannelId(bare));
		} else {
			result.emplace(UserId(bare));
		}
	}
	for (const auto id : _state.snapshot().hiddenPeers) {
		result.emplace(id);
	}
	if (extra) {
		result.emplace(extra);
	}
	const auto original = result;
	for (const auto peer : original) {
		if (const auto loaded = _session->data().peerLoaded(peer)) {
			if (const auto from = loaded->migrateFrom()) {
				result.emplace(from->id);
			}
			if (const auto to = loaded->migrateTo()) {
				result.emplace(to->id);
			}
		}
	}
	return result;
}

void PrivateSpace::transition(Fn<void()> change, PeerId extraPeer, bool allPeers) {
	const auto weak = base::make_weak(_session.get());
	const auto peers = affectedPeers(extraPeer, allPeers);
	if (active() || _managementAuthorized || allPeers) {
		closePrivateViews(peers);
		if (!weak) {
			return;
		}
	}
	for (const auto peer : peers) {
		if (const auto history = _session->data().historyLoaded(peer)) {
			_session->data().removeChatListEntry(history);
			if (!weak) {
				return;
			}
			history->clearPrivateDrafts();
			if (!weak) {
				return;
			}
		}
	}
	change();
	if (!weak) {
		return;
	}
	Core::App().notifications().clearFromSession(_session);
	if (!weak) {
		return;
	}
	for (const auto peer : peers) {
		if (const auto history = _session->data().historyLoaded(peer)) {
			history->updateChatListExistence();
			if (!weak) {
				return;
			}
			if (!allowsPeer(peer)) {
				_session->data().contactsNoChatsList()->remove(history);
			} else if (!history->inChatList()
				&& _session->data().contactsList()->contains(history)) {
				_session->data().contactsNoChatsList()->addByName(history);
			}
			if (!weak) {
				return;
			}
		}
	}
	_session->data().notifyUnreadBadgeChanged();
	if (weak) {
		_changes.fire({});
	}
}

void PrivateSpace::closePrivateViews(const std::set<PeerId> &peers) {
	const auto weak = base::make_weak(_session.get());
	Iv::Editor::CloseWindowsForSession(_session);
	if (!weak) {
		return;
	}
	Core::App().hideMediaView();
	Media::Player::instance()->stopAndClose();
	if (!weak) {
		return;
	}
	for (const auto peer : peers) {
		if (const auto loaded = _session->data().peerLoaded(peer)) {
			Core::App().closeChatFromWindows(loaded);
			if (!weak) {
				return;
			}
		}
	}
	auto windows = std::vector<base::weak_ptr<Window::SessionController>>();
	for (const auto window : _session->windows()) {
		windows.push_back(base::make_weak(window));
	}
	for (const auto &window : windows) {
		if (window) {
			window->hideLayer(anim::type::instant);
		}
		if (window) {
			window->hideSpecialLayer(anim::type::instant);
		}
		if (window) {
			window->clearSectionStack(Window::SectionShow(
				Window::SectionShow::Way::ClearStack,
				anim::type::instant,
				anim::activation::background));
		}
	}
}

void PrivateSpace::read(const QByteArray &serialized) {
	if (serialized.isEmpty()) {
		return;
	}
	_damaged = true;
	if (serialized.size() > 3 * 1024 * 1024) {
		return;
	}
	auto stream = QDataStream(serialized);
	stream.setVersion(QDataStream::Qt_5_1);
	auto version = qint32(0);
	auto attempts = qint32(0);
	auto count = qint32(0);
	auto salt = QByteArray();
	auto digest = QByteArray();
	stream >> version >> salt >> digest >> attempts >> count;
	const auto hasPin = salt.size() == 16 && digest.size() == 32;
	if ((version != 1 && version != 2 && version != kVersion)
		|| (!hasPin && (version < 3 || !salt.isEmpty() || !digest.isEmpty() || count))
		|| attempts < 0
		|| attempts > 5
		|| count < 0
		|| count > kMaximumPeers) {
		return;
	}
	auto snapshot = PrivateSpaceSnapshot();
	for (auto i = 0; i != count; ++i) {
		auto id = quint64(0);
		stream >> id;
		if (!id || ServicePeer(PeerId(id))
			|| !snapshot.hiddenPeers.emplace(id).second) {
			return;
		}
	}
	if (version >= 2) {
		auto timeout = qint32(0);
		auto screenshots = qint32(0);
		stream >> timeout >> screenshots;
		if (timeout < 0 || (screenshots != 0 && screenshots != 1)) {
			return;
		}
		_pinTimeoutMinutes = timeout;
		_allowScreenshots = screenshots != 0;
		_pinWindow.setTimeout(std::chrono::minutes(timeout));
	}
	if (version >= 3) {
		auto messages = QByteArray();
		stream >> messages;
		if (!restorePrivateMessages(messages)) {
			return;
		}
	}
	if (stream.status() != QDataStream::Ok
		|| !stream.atEnd()
		|| !_state.restore(snapshot)) {
		return;
	}
	if (hasPin) {
		auto pin = LocalPin();
		std::copy(salt.begin(), salt.end(), pin.salt.begin());
		std::copy(digest.begin(), digest.end(), pin.digest.begin());
		_pin = pin;
	}
	_failedAttempts = attempts;
	_blockedUntil = (attempts == 5) ? crl::now() + kRetryDelay : 0;
	_damaged = false;
}

void PrivateSpace::save() {
	if (_damaged) {
		return;
	}
	auto serialized = QByteArray();
	if (_pin || !_messageChanges.empty() || !_selfPinChanges.empty() || !_searchChanges.empty()) {
		auto stream = QDataStream(&serialized, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << kVersion
			<< (_pin ? QByteArray(reinterpret_cast<const char*>(_pin->salt.data()), 16) : QByteArray())
			<< (_pin ? QByteArray(reinterpret_cast<const char*>(_pin->digest.data()), 32) : QByteArray())
			<< qint32(_failedAttempts)
			<< qint32(_state.snapshot().hiddenPeers.size());
		for (const auto peer : _state.snapshot().hiddenPeers) {
			stream << quint64(peer);
		}
		stream << qint32(_pinTimeoutMinutes) << qint32(_allowScreenshots ? 1 : 0)
			<< serializePrivateMessages();
	}
	_session->settings().setLeemenPrivateSpace(std::move(serialized));
	if (_syncEnabled && _sync && !_damaged) {
		saveSync();
	} else {
		persistProtection();
	}
}

void PrivateSpace::persistProtection() {
	if (_session->local().writeLeemenSettingsSync()) {
		return;
	}
	protectionPersistenceFailed();
}

void PrivateSpace::protectionPersistenceFailed() {
	const auto weak = base::make_weak(_session.get());
	_damaged = true;
	_session->settings().markSessionSettingsReadFailed();
	_pinWindow.clear();
	cancelPinOperation(_pendingPinRequest);
	if (_sync) {
		_sync->stop();
	}
	if (weak) {
		transition([&] {
			_managementAuthorized = false;
			_state.setActive(false);
		}, 0, true);
	}
}

} // namespace Leemen
