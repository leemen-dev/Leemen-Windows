#pragma once

#include "data/data_peer_id.h"
#include "leemen/local_pin.h"
#include "leemen/private_space_state.h"

#include <rpl/event_stream.h>
#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace Main {
class Session;
} // namespace Main

namespace Leemen {

class PrivateSpace final {
public:
	explicit PrivateSpace(not_null<Main::Session*> session);

	void start();
	[[nodiscard]] static bool EnrollmentEnabled();
	[[nodiscard]] bool configured() const;
	[[nodiscard]] bool damaged() const;
	[[nodiscard]] bool active() const;
	[[nodiscard]] bool hidden(PeerId peer) const;
	[[nodiscard]] bool allowsPeer(PeerId peer) const;
	[[nodiscard]] bool canHide(PeerId peer) const;
	[[nodiscard]] int hiddenCount() const;
	[[nodiscard]] int retryAfterSeconds() const;
	[[nodiscard]] rpl::producer<> changes() const;

	[[nodiscard]] std::uint64_t setPin(const QString &pin, Fn<void(bool)> done);
	[[nodiscard]] std::uint64_t unlock(const QString &pin, Fn<void(bool)> done);
	void cancelPinOperation(std::uint64_t request);
	void lock();
	bool setHidden(PeerId peer, bool hidden);
	bool disable();

private:
	void read(const QByteArray &serialized);
	void save();
	void transition(Fn<void()> change, PeerId extraPeer = 0);
	void closePrivateViews();
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
	[[nodiscard]] std::set<PeerId> affectedPeers(PeerId extra) const;

	const not_null<Main::Session*> _session;
	PrivateSpaceState _state;
	std::optional<LocalPin> _pin;
	bool _damaged = false;
	bool _started = false;
	int _failedAttempts = 0;
	crl::time _blockedUntil = 0;
	std::uint64_t _pinGeneration = 0;
	std::uint64_t _pendingPinRequest = 0;
	rpl::event_stream<> _changes;
	rpl::lifetime _lifetime;

};

} // namespace Leemen
