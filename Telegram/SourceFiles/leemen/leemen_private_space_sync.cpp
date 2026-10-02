#include "leemen/leemen_private_space.h"

#include "base/weak_ptr.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_session.h"
#include "leemen/sync_crypto.h"
#include "leemen/sync_peer_id.h"
#include "leemen/sync_service.h"
#include "main/main_session.h"
#include "main/main_account.h"
#include "main/main_session_settings.h"

#include <crl/crl_async.h>
#include <crl/crl_on_main.h>
#include <algorithm>
#include <limits>
#include <openssl/crypto.h>
#include <QtCore/QDataStream>
#include <QtCore/QIODevice>
#include <QtCore/QUuid>

namespace Leemen {
namespace {

std::span<const unsigned char> Bytes(const QByteArray &bytes) {
	return { reinterpret_cast<const unsigned char*>(bytes.constData()),
		std::size_t(bytes.size()) };
}

std::string Base64(std::span<const unsigned char> bytes) {
	return QByteArray(reinterpret_cast<const char*>(bytes.data()), int(bytes.size()))
		.toBase64().toStdString();
}

bool HasPin(const std::optional<Sync::SyncPair> &projection) {
	return projection && projection->content.pin
		&& projection->content.pin->state == "set";
}

std::uint64_t Reject(Fn<void(bool)> done) {
	crl::on_main([done = std::move(done)] { done(false); });
	return 0;
}

} // namespace

bool PrivateSpace::syncEnabled() const {
	return _syncEnabled;
}

bool PrivateSpace::needsPinSetup() const {
	return _syncEnabled && _sync && _sync->projection()
		&& !_pin && !HasPin(_syncProjection);
}

bool PrivateSpace::usesSyncedPin() const {
	return _syncEnabled && HasPin(_syncProjection);
}

SyncService &PrivateSpace::syncService() {
	Expects(_sync != nullptr);
	return *_sync;
}

bool PrivateSpace::enableSync() {
	if (_syncEnabled || _damaged || !EnrollmentEnabled()
		|| (configured() && !active())) {
		return false;
	}
	const auto weak = base::make_weak(_session);
	_syncDevice = QUuid::createUuid().toString(QUuid::WithoutBraces);
	_syncEnabled = _syncTrusted = true;
	transition([&] {
		_syncTrusted = false;
		_state.setActive(false);
	});
	if (!weak || _damaged) return false;
	startSync();
	return weak && !_damaged;
}

void PrivateSpace::startSync() {
	if (_sync || _damaged) {
		return;
	}
	const auto weak = base::make_weak(_session);
	_sync = std::make_unique<SyncService>(_session);
	const auto &saved = _session->settings().leemenSync();
	if (!saved.isEmpty()) {
		if (saved.size() > 2 * 1024 * 1024) {
			_damaged = true;
			return;
		}
		auto stream = QDataStream(saved);
		stream.setVersion(QDataStream::Qt_5_1);
		auto version = qint32(0);
		auto service = QByteArray();
		stream >> version >> _syncDevice >> service;
		auto attempts = qint32(0);
		if (!stream.atEnd()) {
			stream >> attempts;
		}
		if (version >= 2) {
			auto reset = qint32(0);
			auto count = qint32(0);
			stream >> reset;
			if (version >= 3 && reset == 1) {
				auto clock = qint64(0);
				auto device = QString();
				stream >> clock >> device;
				if (clock <= 0 || device.isEmpty() || device.size() > 256) {
					_damaged = true;
					return;
				}
				_syncDisableLocal = Sync::LocalIntentStamp{ clock, device.toStdString() };
			}
			stream >> count;
			if ((reset != 0 && reset != 1) || count < 0 || count > 100000) {
				_damaged = true;
				return;
			}
			auto seen = std::set<std::uint64_t>();
			for (auto index = 0; index != count; ++index) {
				auto peer = quint64(0);
				stream >> peer;
				if (!Sync::CanonicalPeerId(PeerId(peer))
					|| !seen.emplace(peer).second) {
					_damaged = true;
					return;
				}
				// Older journals cannot prove which operation removed a local peer.
				if (version >= 3) {
					auto clock = qint64(0);
					auto device = QString();
					stream >> clock >> device;
					if (clock <= 0 || device.isEmpty() || device.size() > 256) {
						_damaged = true;
						return;
					}
					_syncLocalRemovals.emplace(peer,
						Sync::LocalIntentStamp{ clock, device.toStdString() });
				}
			}
		}
		if ((version != 1 && version != 2 && version != 3)
			|| stream.status() != QDataStream::Ok || !stream.atEnd()
			|| attempts < 0 || attempts > 5
			|| QUuid(_syncDevice).isNull()
			|| (!_sync->restore(service) && !service.isEmpty())) {
			_damaged = true;
			return;
		}
		_failedAttempts = std::max(_failedAttempts, int(attempts));
		if (_failedAttempts == 5) {
			_blockedUntil = crl::now() + crl::time(30000);
		}
	}
	_sync->changes() | rpl::on_next([=] { syncChanged(); }, _lifetime);
	saveSync();
	if (weak && !_damaged) {
		_sync->start();
	}
}

void PrivateSpace::saveSync() {
	if (!_sync || _damaged) {
		return;
	}
	auto bytes = QByteArray();
	auto stream = QDataStream(&bytes, QIODevice::WriteOnly);
	stream.setVersion(QDataStream::Qt_5_1);
	stream << qint32(3) << _syncDevice << _sync->serialize() << qint32(_failedAttempts)
		<< qint32(_syncDisableLocal ? 1 : 0);
	if (_syncDisableLocal) {
		stream << qint64(_syncDisableLocal->clock)
			<< QString::fromStdString(_syncDisableLocal->device);
	}
	stream << qint32(_syncLocalRemovals.size());
	for (const auto &[peer, stamp] : _syncLocalRemovals) {
		stream << quint64(peer) << qint64(stamp.clock)
			<< QString::fromStdString(stamp.device);
	}
	_session->settings().setLeemenSync(std::move(bytes));
	persistProtection();
}

void PrivateSpace::syncChanged() {
	if (_damaged) {
		return;
	}
	if (_syncApplying) {
		_syncChangePending = true;
		return;
	}
	_syncApplying = true;
	_syncChangePending = false;
	const auto weak = base::make_weak(_session);
	const auto canContinue = [&] {
		if (!weak) return false;
		if (_damaged) _syncApplying = false;
		return !_damaged;
	};
	if (_sync->state() == SyncService::State::AccountDeleted
		&& !_syncDeletedLogoutScheduled) {
		_syncDeletedLogoutScheduled = true;
		crl::on_main(_session, [=] {
			if (_sync && _sync->state() == SyncService::State::AccountDeleted
				&& _session->account().maybeSession() == _session.get()) {
				_session->account().forcedLogOut();
			}
		});
	}
	if (_sync->resetState() == SyncService::ResetState::Confirmed) {
		auto done = std::move(_syncPinDone);
		_syncPinDone = nullptr;
		cancelPinOperation(_pendingPinRequest);
		transition([&] {
			_state = PrivateSpaceState();
			_pin.reset();
			_managementAuthorized = false;
			_pinWindow.clear();
			_pinWindow.setTimeout({});
			_pinTimeoutMinutes = 0;
			_allowScreenshots = true;
			_failedAttempts = 0;
			_blockedUntil = 0;
			_messageChanges.clear();
			_selfPinChanges.clear();
			_searchChanges.clear();
			_messageEpochKnown = false;
			_messagePinEpoch.reset();
			_syncHidden.clear();
			_syncProjection.reset();
			_syncTrusted = false;
			_syncLocalRemovals.clear();
			_syncDisableLocal.reset();
			_syncImportUnlockRequest = 0;
			save();
		});
		if (!canContinue()) {
			if (done) {
				done(false);
			}
			return;
		}
		_sync->completeLocalReset();
		if (!canContinue()) {
			if (done) done(false);
			return;
		}
		saveSync();
		if (!canContinue()) {
			if (done) done(false);
			return;
		}
		_syncApplying = false;
		if (_syncChangePending) {
			syncChanged();
		}
		if (done) {
			done(false);
		}
		return;
	}
	if (_sync->error() == SyncService::Error::AuthorizationChanged
		|| _sync->error() == SyncService::Error::GenerationChanged
		|| _sync->state() == SyncService::State::AccountDeleted
		|| (_sync->state() == SyncService::State::Blocked
			&& _sync->error() == SyncService::Error::None && !_sync->pendingMutation())) {
		invalidatePrivateMessageIntents();
		if (!canContinue()) return;
	}
	if (_sync->error() == SyncService::Error::AuthorizationChanged
		|| _sync->error() == SyncService::Error::GenerationChanged
		|| _sync->state() == SyncService::State::AccountDeleted
		|| (!_sync->projection() && !_sync->pendingMutation())) {
		_syncLocalRemovals.clear();
		_syncDisableLocal.reset();
	}
	const auto projected = _sync->projection()
		? std::make_optional(*_sync->projection())
		: std::nullopt;
	const auto reading = _sync->state() == SyncService::State::Reading;
	const auto writing = _sync->state() == SyncService::State::Writing;
	const auto pending = _sync->pendingMutation();
	const auto unchangedAccess = !pending || (_syncProjection
		&& Sync::CanRetainTrustedProjection(*_syncProjection, *pending));
	const auto trusted = projected
		|| ((reading || writing) && _syncTrusted && unchangedAccess);
	if (active() && requiresLimitResolution()) {
		transition([&] { _state.setActive(false); });
		if (!canContinue()) return;
	}
	if (projected) {
		auto hidden = std::set<std::int64_t>();
		for (const auto &[key, value] : projected->filter.hiddenChatIds) {
			if (Sync::ProtectsMembership(value)) {
				if (const auto id = Sync::ParseCanonicalPeerKey(key)) {
					hidden.emplace(*id);
				}
			}
		}
		const auto pinChanged = !_syncProjection
			|| _syncProjection->content.pin != projected->content.pin;
		const auto timeout = projected->content.settings.pinTimeoutMinutes;
		const auto minutes = timeout
			? int(std::min(timeout->value, std::int64_t(std::numeric_limits<int>::max())))
			: 0;
		const auto screenshots = projected->content.settings.allowScreenshots;
		const auto migrated = projected->content.pin
			&& projected->content.pin->state == "set"
			&& std::all_of(_state.snapshot().hiddenPeers.begin(),
				_state.snapshot().hiddenPeers.end(), [&](std::uint64_t peer) {
					const auto id = Sync::CanonicalPeerId(PeerId(peer));
					return id && hidden.contains(*id);
				});
		const auto disabled = _syncDisableLocal
			&& Sync::IsConfirmedLocalDisable(
				projected->filter, projected->content, *_syncDisableLocal);
		const auto apply = [&] {
			if (!_sync->projection() || _syncChangePending) {
				_syncTrusted = false;
				_state.setActive(false);
				_pinWindow.clear();
				_syncChangePending = true;
				return;
			}
			const auto removals = _syncLocalRemovals;
			for (const auto &[peer, stamp] : removals) {
				const auto id = Sync::CanonicalPeerId(PeerId(peer));
				if (id && Sync::IsConfirmedLocalRemoval(projected->filter, *id, stamp)) {
					_state.setHidden(peer, false);
					forgetPrivateMessages(PeerId(peer));
					if (!canContinue()) return;
					save();
					if (!canContinue()) return;
				}
			}
			_syncLocalRemovals.clear();
			if ((migrated || disabled) && (_pin || !_state.snapshot().hiddenPeers.empty())) {
				const auto wasActive = _state.active();
				_state = PrivateSpaceState();
				_state.setActive(wasActive && !disabled);
				_pin.reset();
				save();
				if (!canContinue()) return;
			}
			_syncDisableLocal.reset();
			_syncProjection = *projected;
			_syncHidden = std::move(hidden);
			_syncTrusted = true;
			reconcilePrivateMessages();
			if (!canContinue()) return;
			_pinTimeoutMinutes = minutes;
			_pinWindow.setTimeout(std::chrono::minutes(minutes));
			_allowScreenshots = screenshots ? screenshots->value : true;
			if (requiresLimitResolution()) {
				_state.setActive(false);
			}
			if (pinChanged) {
				_managementAuthorized = false;
				_pinWindow.clear();
				_state.setActive(false);
				cancelPinOperation(_pendingPinRequest);
			}
		};
		if (!_syncTrusted || hidden != _syncHidden || pinChanged) {
			transition(apply);
		} else {
			apply();
			if (!canContinue()) return;
			_changes.fire({});
		}
	} else if (_syncTrusted != trusted) {
		transition([&] {
			_syncTrusted = trusted;
			_managementAuthorized = false;
			_state.setActive(false);
			_pinWindow.clear();
			if (!_syncImportUnlockRequest || _pendingPinRequest != _syncImportUnlockRequest) {
				cancelPinOperation(_pendingPinRequest);
			}
		});
	} else {
		_changes.fire({});
	}
	if (!canContinue()) return;
	saveSync();
	if (!canContinue()) return;
	_syncApplying = false;
	if (_syncChangePending) {
		syncChanged();
		return;
	}
	if (_syncPinDone && _sync->state() != SyncService::State::Reading
		&& _sync->state() != SyncService::State::Writing) {
		auto done = std::move(_syncPinDone);
		_syncPinDone = nullptr;
		done(_sync->projection() != nullptr);
	}
}

bool PrivateSpace::syncMutate(
		Fn<void(Sync::FilterBlob&, Sync::ContentBlob&, std::int64_t)> change) {
	if (!_sync || !_sync->projection()) {
		return false;
	}
	auto pair = *_sync->projection();
	const auto clock = Sync::NextLamport(pair.filter, pair.content);
	if (!clock) {
		return false;
	}
	const auto weak = base::make_weak(_session);
	change(pair.filter, pair.content, *clock);
	return weak && !_damaged
		&& _sync->submit(std::move(pair.filter), std::move(pair.content));
}

bool PrivateSpace::syncSetHidden(PeerId peer, bool hide) {
	const auto id = Sync::CanonicalPeerId(peer);
	if (!id) {
		return false;
	}
	auto peers = std::set<PeerId>{ peer };
	if (!hide) {
		if (const auto loaded = _session->data().peerLoaded(peer)) {
			if (const auto from = loaded->migrateFrom()) {
				peers.emplace(from->id);
			}
			if (const auto to = loaded->migrateTo()) {
				peers.emplace(to->id);
			}
		}
	}
	const auto previousRemovals = _syncLocalRemovals;
	const auto weak = base::make_weak(_session);
	const auto submitted = syncMutate([=](auto &filter, auto &content, std::int64_t clock) {
		for (const auto peer : peers) {
			if (const auto canonical = Sync::CanonicalPeerId(peer)) {
				const auto key = *Sync::CanonicalPeerKey(*canonical);
				auto &value = filter.hiddenChatIds[key];
				value.state = hide ? "present" : "removed";
				value.clock = clock;
				value.device = _syncDevice.toStdString();
				if (!hide) {
					_syncLocalRemovals[peer.value] = { clock, value.device };
					content.perChat[key].clearedAtClock = clock;
				}
			}
		}
	});
	if (!weak || _damaged) return false;
	if (!submitted) {
		_syncLocalRemovals = previousRemovals;
		saveSync();
	}
	return submitted;
}

bool PrivateSpace::syncDisable() {
	const auto previousDisable = _syncDisableLocal;
	const auto weak = base::make_weak(_session);
	const auto submitted = syncMutate([=](auto &filter, auto &content, std::int64_t clock) {
		_syncDisableLocal = Sync::LocalIntentStamp{ clock, _syncDevice.toStdString() };
		for (auto &[key, value] : filter.hiddenChatIds) {
			if (Sync::ProtectsMembership(value)) {
				value.state = "removed";
				value.clock = clock;
				value.device = _syncDevice.toStdString();
				content.perChat[key].clearedAtClock = clock;
			}
		}
		auto pin = Sync::PinRegister();
		pin.state = "none";
		pin.clock = clock;
		pin.device = _syncDevice.toStdString();
		if (content.pin) {
			pin.unknownFields = content.pin->unknownFields;
		}
		content.pin = std::move(pin);
	});
	if (!weak || _damaged) return false;
	if (!submitted) {
		_syncDisableLocal = previousDisable;
		saveSync();
	}
	return submitted;
}

bool PrivateSpace::syncImportLocal(std::uint64_t request, Fn<void(bool)> done) {
	if (!HasPin(_syncProjection)
		|| _state.snapshot().hiddenPeers.empty()) {
		return false;
	}
	if (_pendingPinRequest != request || _pinGeneration != request
		|| !pinOperationAllowed()) {
		cancelPinOperation(request);
		done(false);
		return true;
	}
	_syncImportUnlockRequest = request;
	const auto weak = base::make_weak(_session);
	_syncPinDone = crl::guard(_session, [=](bool synced) {
		const auto valid = synced && _pendingPinRequest == request
			&& _pinGeneration == request && HasPin(_syncProjection)
			&& pinOperationAllowed();
		cancelPinOperation(request);
		if (valid) {
			_pinWindow.recordVerified();
			transition([&] {
				_managementAuthorized = true;
				_state.setActive(!requiresLimitResolution());
			});
		}
		done(valid && weak && !_damaged);
	});
	const auto submitted = syncMutate([&](auto &filter, auto &, std::int64_t clock) {
		for (const auto peer : _state.snapshot().hiddenPeers) {
			if (const auto id = Sync::CanonicalPeerId(PeerId(peer))) {
				auto &entry = filter.hiddenChatIds[*Sync::CanonicalPeerKey(*id)];
				entry.state = "present";
				entry.clock = clock;
				entry.device = _syncDevice.toStdString();
			}
		}
	});
	if (!weak || _damaged) return true;
	if (!submitted) {
		_syncPinDone = nullptr;
		cancelPinOperation(request);
		done(false);
	}
	return true;
}

std::uint64_t PrivateSpace::syncUnlock(const QString &pin, Fn<void(bool)> done) {
	if (!pinOperationAllowed() || !HasPin(_syncProjection)
		|| _pendingPinRequest || retryAfterSeconds()) {
		return Reject(std::move(done));
	}
	const auto request = _pendingPinRequest = ++_pinGeneration;
	const auto verifier = *_syncProjection->content.pin;
	const auto weak = base::make_weak(_session);
	crl::async([
		bytes = std::make_unique<QByteArray>(pin.toUtf8()),
		verifier, request, weak, done = std::move(done)
	]() mutable {
		const auto salt = QByteArray::fromBase64(QByteArray::fromStdString(*verifier.salt));
		const auto hash = QByteArray::fromBase64(QByteArray::fromStdString(*verifier.hash));
		const auto valid = Sync::VerifySyncedPin(
			std::string_view(bytes->constData(), bytes->size()), Bytes(salt), Bytes(hash));
		OPENSSL_cleanse(bytes->data(), bytes->size());
		bytes.reset();
		crl::on_main(crl::guard(weak, [=] {
			weak->leemen().finishPinVerification(request, valid, done);
		}));
	});
	return request;
}

std::uint64_t PrivateSpace::syncSetPin(const QString &pin, Fn<void(bool)> done) {
	const auto valid = pin.size() >= 4 && pin.size() <= 6
		&& std::all_of(pin.begin(), pin.end(), [](QChar ch) {
			return ch >= QChar('0') && ch <= QChar('9');
		});
	if (!valid || !pinOperationAllowed() || _pendingPinRequest
		|| (!active() && !needsPinSetup())) {
		return Reject(std::move(done));
	}
	const auto request = _pendingPinRequest = ++_pinGeneration;
	const auto weak = base::make_weak(_session);
	crl::async([
		bytes = std::make_unique<QByteArray>(pin.toUtf8()),
		request, weak, done = std::move(done)
	]() mutable {
		const auto salt = Sync::RandomSalt();
		auto hash = salt ? Sync::DerivePinHash(
			std::string_view(bytes->constData(), bytes->size()), *salt) : std::nullopt;
		OPENSSL_cleanse(bytes->data(), bytes->size());
		bytes.reset();
		auto result = std::optional<Sync::PinRegister>();
		if (salt && hash) {
			result = Sync::PinRegister();
			result->state = "set";
			result->hash = Base64(hash->bytes());
			result->salt = Base64(*salt);
			result->kdf = "argon2id";
		}
		crl::on_main(crl::guard(weak, [=] {
			auto &space = weak->leemen();
			if (!result || space._pendingPinRequest != request
				|| space._pinGeneration != request || !space.pinOperationAllowed()) {
				space.cancelPinOperation(request);
				done(false);
				return;
			}
			space._pendingPinRequest = 0;
			space._syncPinDone = done;
			const auto submitted = space.syncMutate([&](auto &filter, auto &content, std::int64_t clock) {
				auto replacement = *result;
				replacement.clock = clock;
				replacement.device = space._syncDevice.toStdString();
				if (content.pin) {
					replacement.unknownFields = content.pin->unknownFields;
				}
				content.pin = std::move(replacement);
				for (const auto peer : space._state.snapshot().hiddenPeers) {
					if (const auto id = Sync::CanonicalPeerId(PeerId(peer))) {
						auto &entry = filter.hiddenChatIds[*Sync::CanonicalPeerKey(*id)];
						entry.state = "present";
						entry.clock = clock;
						entry.device = space._syncDevice.toStdString();
					}
				}
			});
			if (weak && !submitted && space._syncPinDone) {
				space._syncPinDone = nullptr;
				done(false);
			}
		}));
	});
	return request;
}

} // namespace Leemen
