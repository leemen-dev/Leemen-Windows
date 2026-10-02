#include "leemen/leemen_private_space.h"

#include "core/application.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_session.h"
#include "dialogs/dialogs_indexed_list.h"
#include "history/history.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "main/main_session_settings.h"
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

constexpr auto kVersion = qint32(1);
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
	if (session->settings().sessionSettingsReadFailed()) {
		_damaged = true;
	} else {
		read(session->settings().leemenPrivateSpace());
	}
}

void PrivateSpace::start() {
	_started = true;
	Core::App().appDeactivatedValue() | rpl::on_next([=](bool away) {
		if (away) {
			lock();
		}
	}, _lifetime);
	Core::App().passcodeLockValue() | rpl::on_next([=](bool locked) {
		if (locked) {
			lock();
		}
	}, _lifetime);
	_session->domain().activeValue(
	) | rpl::on_next([=](Main::Account *account) {
		if (account != &_session->account()) {
			lock();
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
	return _pin.has_value() || _damaged;
}

bool PrivateSpace::damaged() const {
	return _damaged;
}

bool PrivateSpace::active() const {
	return !_damaged && _state.active();
}

bool PrivateSpace::hidden(PeerId peer) const {
	if (!peer || ServicePeer(peer)) {
		return false;
	} else if (_damaged || _state.hidden(peer.value)) {
		return true;
	} else if (_started) {
		if (const auto loaded = _session->data().peerLoaded(peer)) {
			if (const auto from = loaded->migrateFrom()) {
				if (_state.hidden(from->id.value)) {
					return true;
				}
			}
			if (const auto to = loaded->migrateTo()) {
				return _state.hidden(to->id.value);
			}
		}
	}
	return false;
}

bool PrivateSpace::allowsPeer(PeerId peer) const {
	return active() || !hidden(peer);
}

bool PrivateSpace::canHide(PeerId peer) const {
	if (!peer || ServicePeer(peer) || peer == _session->userPeerId()) {
		return false;
	}
	const auto loaded = _session->data().peerLoaded(peer);
	return loaded && !loaded->isServiceUser();
}

int PrivateSpace::hiddenCount() const {
	return int(_state.snapshot().hiddenPeers.size());
}

int PrivateSpace::retryAfterSeconds() const {
	return int(std::max(crl::time(0), _blockedUntil - crl::now() + 999) / 1000);
}

rpl::producer<> PrivateSpace::changes() const {
	return _changes.events();
}

bool PrivateSpace::pinOperationAllowed() const {
	return !_damaged
		&& _session->account().maybeSession() == _session.get()
		&& _session->domain().started()
		&& &_session->domain().active() == &_session->account()
		&& QGuiApplication::applicationState() == Qt::ApplicationActive
		&& !Core::App().passcodeLocked();
}

std::uint64_t PrivateSpace::setPin(const QString &pin, Fn<void(bool)> done) {
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
	_failedAttempts = 0;
	_blockedUntil = 0;
	save();
	_session->data().notifyUnreadBadgeChanged();
	_changes.fire({});
	done(true);
}

void PrivateSpace::finishPinVerification(
		std::uint64_t request,
		bool verified,
		Fn<void(bool)> done) {
	if (_pendingPinRequest != request || _pinGeneration != request) {
		done(false);
		return;
	}
	_pendingPinRequest = 0;
	if (!pinOperationAllowed() || !_pin) {
		done(false);
		return;
	}
	if (!verified) {
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
	save();
	transition([&] { _state.setActive(true); });
	done(true);
}

void PrivateSpace::cancelPinOperation(std::uint64_t request) {
	if (request && _pendingPinRequest == request) {
		_pendingPinRequest = 0;
		++_pinGeneration;
	}
}

void PrivateSpace::lock() {
	cancelPinOperation(_pendingPinRequest);
	if (active()) {
		transition([&] { _state.setActive(false); });
	}
}

bool PrivateSpace::setHidden(PeerId peer, bool hide) {
	if (!active() || !canHide(peer) || hidden(peer) == hide) {
		return false;
	}
	transition([&] {
		_state.setHidden(peer.value, hide);
		if (!hide) {
			for (const auto related : affectedPeers(peer)) {
				const auto loaded = _session->data().peerLoaded(peer);
				if (loaded && ((loaded->migrateFrom()
					&& loaded->migrateFrom()->id == related)
					|| (loaded->migrateTo()
						&& loaded->migrateTo()->id == related))) {
					_state.setHidden(related.value, false);
				}
			}
		}
		save();
	}, peer);
	return true;
}

bool PrivateSpace::disable() {
	if (!active()) {
		return false;
	}
	cancelPinOperation(_pendingPinRequest);
	transition([&] {
		_state = PrivateSpaceState();
		_pin.reset();
		_failedAttempts = 0;
		_blockedUntil = 0;
		save();
	});
	return true;
}

std::set<PeerId> PrivateSpace::affectedPeers(PeerId extra) const {
	auto result = std::set<PeerId>();
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

void PrivateSpace::transition(Fn<void()> change, PeerId extraPeer) {
	const auto peers = affectedPeers(extraPeer);
	for (const auto peer : peers) {
		if (const auto history = _session->data().historyLoaded(peer)) {
			_session->data().removeChatListEntry(history);
		}
	}
	change();
	Core::App().notifications().clearFromSession(_session);
	if (!active()) {
		closePrivateViews();
	}
	for (const auto peer : peers) {
		if (const auto history = _session->data().historyLoaded(peer)) {
			history->updateChatListExistence();
			if (!allowsPeer(peer)) {
				_session->data().contactsNoChatsList()->remove(history);
			} else if (!history->inChatList()
				&& _session->data().contactsList()->contains(history)) {
				_session->data().contactsNoChatsList()->addByName(history);
			}
		}
	}
	_session->data().notifyUnreadBadgeChanged();
	_changes.fire({});
}

void PrivateSpace::closePrivateViews() {
	Core::App().hideMediaView();
	Media::Player::instance()->stopAndClose();
	for (const auto peer : affectedPeers(0)) {
		if (const auto loaded = _session->data().peerLoaded(peer)) {
			Core::App().closeChatFromWindows(loaded);
		}
	}
	const auto windows = _session->windows();
	for (const auto window : windows) {
		window->hideLayer(anim::type::instant);
		window->hideSpecialLayer(anim::type::instant);
		window->clearSectionStack(Window::SectionShow(
			Window::SectionShow::Way::ClearStack,
			anim::type::instant,
			anim::activation::background));
	}
}

void PrivateSpace::read(const QByteArray &serialized) {
	if (serialized.isEmpty()) {
		return;
	}
	_damaged = true;
	if (serialized.size() > 1024 * 1024) {
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
	if (version != kVersion
		|| salt.size() != 16
		|| digest.size() != 32
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
	if (stream.status() != QDataStream::Ok
		|| !stream.atEnd()
		|| !_state.restore(snapshot)) {
		return;
	}
	auto pin = LocalPin();
	std::copy(salt.begin(), salt.end(), pin.salt.begin());
	std::copy(digest.begin(), digest.end(), pin.digest.begin());
	_pin = pin;
	_failedAttempts = attempts;
	_blockedUntil = (attempts == 5) ? crl::now() + kRetryDelay : 0;
	_damaged = false;
}

void PrivateSpace::save() {
	auto serialized = QByteArray();
	if (_pin) {
		auto stream = QDataStream(&serialized, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << kVersion
			<< QByteArray(reinterpret_cast<const char*>(_pin->salt.data()), 16)
			<< QByteArray(reinterpret_cast<const char*>(_pin->digest.data()), 32)
			<< qint32(_failedAttempts)
			<< qint32(_state.snapshot().hiddenPeers.size());
		for (const auto peer : _state.snapshot().hiddenPeers) {
			stream << quint64(peer);
		}
	}
	_session->settings().setLeemenPrivateSpace(std::move(serialized));
	_session->saveSettings();
}

} // namespace Leemen
