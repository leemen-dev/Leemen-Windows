#pragma once

#include "data/data_peer_id.h"
#include "data/data_msg_id.h"
#include "leemen/local_pin.h"
#include "leemen/private_space_state.h"
#include "leemen/sync_coordinator.h"
#include "leemen/sync_local_intents.h"

#include <rpl/event_stream.h>
#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace Main {
class Session;
} // namespace Main

namespace Leemen {

class SyncService;

class PrivateSpace final {
public:
	explicit PrivateSpace(not_null<Main::Session*> session);
	~PrivateSpace();

	void start();
	void accountVisibilityChanged();
	[[nodiscard]] static bool EnrollmentEnabled();
	[[nodiscard]] bool configured() const;
	[[nodiscard]] bool damaged() const;
	[[nodiscard]] bool active() const;
	[[nodiscard]] bool hidden(PeerId peer) const;
	[[nodiscard]] bool allowsPeer(PeerId peer) const;
	[[nodiscard]] bool canHide(PeerId peer) const;
	[[nodiscard]] bool messageStateReady() const;
	[[nodiscard]] MessageState messageState(FullMsgId id) const;
	[[nodiscard]] bool allowsMessage(FullMsgId id, bool outgoingInFlight = false) const;
	[[nodiscard]] std::vector<FullMsgId> publicMessages(PeerId peer) const;
	[[nodiscard]] std::vector<FullMsgId> pendingMessages() const;
	bool setMessageState(FullMsgId id, MessageState state);
	void resolvePendingMessages(const std::vector<FullMsgId> &ids, MessageState state);
	bool markOffModeMessage(FullMsgId id);
	void markOffModePinService(FullMsgId id, FullMsgId target, bool outgoing);
	void replacePrivateMessageId(FullMsgId oldId, MsgId newId);
	void forgetPrivateMessages(PeerId peer);
	[[nodiscard]] bool selfPinned(FullMsgId id) const;
	void recordSelfPin(FullMsgId id, bool pinned);
	[[nodiscard]] bool privateSearch(PeerId peer) const;
	[[nodiscard]] bool allowsRecentSearch(PeerId peer) const;
	void recordSearch(PeerId peer);
	[[nodiscard]] int hiddenCount() const;
	[[nodiscard]] bool requiresLimitResolution() const;
	[[nodiscard]] bool managementAllowed() const;
	[[nodiscard]] bool canAddHiddenChat(PeerId peer) const;
	[[nodiscard]] std::vector<PeerId> hiddenPeersForManagement() const;
	[[nodiscard]] int retryAfterSeconds() const;
	[[nodiscard]] int pinTimeoutMinutes() const;
	[[nodiscard]] bool screenshotsAllowed() const;
	[[nodiscard]] bool syncEnabled() const;
	[[nodiscard]] bool needsPinSetup() const;
	[[nodiscard]] bool usesSyncedPin() const;
	[[nodiscard]] SyncService &syncService();
	bool enableSync();
	[[nodiscard]] rpl::producer<> changes() const;

	[[nodiscard]] std::uint64_t setPin(const QString &pin, Fn<void(bool)> done);
	[[nodiscard]] std::uint64_t unlock(const QString &pin, Fn<void(bool)> done);
	void cancelPinOperation(std::uint64_t request);
	void lock(bool clearVerification = false);
	bool unlockWithinGrace();
	bool setPinTimeoutMinutes(int minutes);
	bool setScreenshotsAllowed(bool allowed);
	bool setHidden(PeerId peer, bool hidden);
	bool disable();

private:
	void read(const QByteArray &serialized);
	void save();
	void initPrivateMessages();
	void reconcilePrivateMessages();
	void invalidatePrivateMessageIntents();
	void bindPrivateMessageIntents();
	void flushPrivateMessages();
	[[nodiscard]] QByteArray serializePrivateMessages() const;
	bool restorePrivateMessages(const QByteArray &bytes);
	void startSync();
	void saveSync();
	void syncChanged();
	bool syncSetHidden(PeerId peer, bool hide);
	bool syncDisable();
	bool syncImportLocal(std::uint64_t request, Fn<void(bool)> done);
	bool syncMutate(Fn<void(Sync::FilterBlob&, Sync::ContentBlob&, std::int64_t)> change);
	std::uint64_t syncSetPin(const QString &pin, Fn<void(bool)> done);
	std::uint64_t syncUnlock(const QString &pin, Fn<void(bool)> done);
	void transition(Fn<void()> change, PeerId extraPeer = 0, bool allPeers = false);
	void closePrivateViews(const std::set<PeerId> &peers);
	void finishPinCreation(
		std::uint64_t request,
		bool enrolled,
		std::optional<LocalPin> replacement,
		Fn<void(bool)> done);
	void finishPinVerification(
		std::uint64_t request,
		bool verified,
		Fn<void(bool)> done);
	[[nodiscard]] bool pinOperationAllowed() const;
	[[nodiscard]] std::set<PeerId> affectedPeers(PeerId extra, bool allPeers = false) const;

	const not_null<Main::Session*> _session;
	PrivateSpaceState _state;
	std::optional<LocalPin> _pin;
	std::map<FullMsgId, Sync::Register> _messageChanges;
	std::map<FullMsgId, Sync::Register> _selfPinChanges;
	std::map<PeerId, Sync::Register> _searchChanges;
	bool _messageFlushScheduled = false;
	bool _messageEpochKnown = false;
	std::optional<Sync::PinRegister> _messagePinEpoch;
	bool _damaged = false;
	bool _started = false;
	bool _accountContentAllowed = true;
	bool _managementAuthorized = false;
	int _failedAttempts = 0;
	crl::time _blockedUntil = 0;
	std::uint64_t _pinGeneration = 0;
	std::uint64_t _pendingPinRequest = 0;
	PinVerificationWindow _pinWindow;
	int _pinTimeoutMinutes = 0;
	bool _allowScreenshots = true;
	bool _syncEnabled = false;
	bool _syncTrusted = false;
	bool _syncApplying = false;
	bool _syncChangePending = false;
	std::optional<Sync::LocalIntentStamp> _syncDisableLocal;
	std::uint64_t _syncImportUnlockRequest = 0;
	QString _syncDevice;
	std::unique_ptr<SyncService> _sync;
	std::optional<Sync::SyncPair> _syncProjection;
	std::set<std::int64_t> _syncHidden;
	std::map<std::uint64_t, Sync::LocalIntentStamp> _syncLocalRemovals;
	Fn<void(bool)> _syncPinDone;
	rpl::event_stream<> _changes;
	rpl::lifetime _lifetime;

};

} // namespace Leemen
