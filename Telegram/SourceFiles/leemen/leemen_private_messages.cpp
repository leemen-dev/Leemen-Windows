#include "leemen/leemen_private_space.h"

#include "base/weak_ptr.h"
#include "leemen/private_message_policy.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/leemen_private_messages_box.h"
#include "leemen/sync_peer_id.h"
#include "leemen/sync_service.h"
#include "main/main_session.h"

#include <crl/crl_on_main.h>
#include <QtCore/QDataStream>
#include <QtCore/QIODevice>
#include <limits>
#include <type_traits>

namespace Leemen {
namespace {

constexpr auto kMaximumEntries = 100000;
constexpr auto kLocalOnlyClock = std::numeric_limits<std::int64_t>::max();

std::string StateName(MessageState state) {
	return state == MessageState::Exposed ? "exposed"
		: state == MessageState::Pending ? "pending" : "hidden";
}

MessageState StateValue(const std::string &state) {
	return state == "exposed" ? MessageState::Exposed
		: state == "pending" ? MessageState::Pending : MessageState::Hidden;
}

bool ValidId(FullMsgId id) {
	return Sync::CanonicalPeerId(id.peer).has_value()
		&& (IsServerMsgId(id.msg) || IsClientMsgId(id.msg));
}

} // namespace

bool PrivateSpace::messageStateReady() const {
	return PrivateAccountContentAllowed(_session) && !_damaged
		&& (!_syncEnabled || (_syncTrusted && _syncProjection));
}

MessageState PrivateSpace::messageState(FullMsgId id) const {
	if (!messageStateReady() || !ValidId(id)) {
		return MessageState::Hidden;
	}
	const auto local = _messageChanges.find(id);
	if (local != _messageChanges.end()
		&& (!_syncEnabled || local->second.state != "exposed")) {
		return StateValue(local->second.state);
	}
	const auto peer = Sync::CanonicalPeerId(id.peer);
	return (_syncEnabled && peer && _syncProjection)
		? SyncedMessageState(_syncProjection->content, *peer, id.msg.bare)
		: MessageState::Hidden;
}

bool PrivateSpace::allowsMessage(FullMsgId id, bool outgoingInFlight) const {
	return ValidId(id) && messageStateReady()
		&& (allowsPeer(id.peer) || outgoingInFlight
			|| messageState(id) != MessageState::Hidden);
}

std::vector<FullMsgId> PrivateSpace::publicMessages(PeerId peer) const {
	auto ids = std::set<FullMsgId>();
	if (!messageStateReady() || !hidden(peer)) {
		return {};
	}
	if (const auto canonical = Sync::CanonicalPeerId(peer)
		; canonical && _syncProjection) {
		const auto chat = _syncProjection->content.perChat.find(
			*Sync::CanonicalPeerKey(*canonical));
		if (chat != _syncProjection->content.perChat.end()) {
			for (const auto &[key, value] : chat->second.messageState) {
				if (const auto message = Sync::ParseCloudMessageKey(key)) {
					ids.emplace(peer, MsgId(*message));
				}
			}
		}
	}
	for (const auto &[id, value] : _messageChanges) {
		if (id.peer == peer) {
			ids.emplace(id);
		}
	}
	auto result = std::vector<FullMsgId>();
	for (const auto id : ids) {
		if (messageState(id) != MessageState::Hidden) {
			result.push_back(id);
		}
	}
	return result;
}

bool PrivateSpace::setMessageState(FullMsgId id, MessageState state) {
	if (!active() || !hidden(id.peer) || !ValidId(id)
		|| (state != MessageState::Hidden && state != MessageState::Exposed)) {
		return false;
	}
	bindPrivateMessageIntents();
	_messageChanges[id] = { StateName(state), 0, "local", {} };
	save();
	_changes.fire({});
	return true;
}

bool PrivateSpace::markOffModeMessage(FullMsgId id) {
	if (active() || !messageStateReady() || !hidden(id.peer)
		|| !ValidId(id) || !IsClientMsgId(id.msg)) {
		return false;
	}
	bindPrivateMessageIntents();
	_messageChanges[id] = { "pending", 0, "local", {} };
	save();
	_changes.fire({});
	return true;
}

void PrivateSpace::resolvePendingMessages(
		const std::vector<FullMsgId> &ids,
		MessageState state) {
	if (!active()
		|| (state != MessageState::Hidden && state != MessageState::Exposed)) {
		return;
	}
	bindPrivateMessageIntents();
	auto changed = false;
	for (const auto id : ids) {
		if (hidden(id.peer) && ValidId(id)
			&& messageState(id) == MessageState::Pending) {
			_messageChanges[id] = { StateName(state), 0, "local", {} };
			changed = true;
		}
	}
	if (changed) {
		save();
		_changes.fire({});
	}
}

void PrivateSpace::markOffModePinService(
		FullMsgId id,
		FullMsgId target,
		bool outgoing) {
	if (active() || !messageStateReady() || !hidden(id.peer)
		|| !ValidId(id) || !IsServerMsgId(id.msg) || !ValidId(target)
		|| !VisibleOwnPinService(outgoing, id.peer == target.peer, messageState(target))
		|| messageState(id) == MessageState::Pending) {
		return;
	}
	bindPrivateMessageIntents();
	_messageChanges[id] = { "pending", 0, "local", {} };
	save();
	// Service items may still be under construction when this hook runs.
	crl::on_main(_session, [=] { _changes.fire({}); });
}

void PrivateSpace::replacePrivateMessageId(FullMsgId oldId, MsgId newId) {
	if (!IsServerMsgId(newId) || oldId.msg == newId) {
		return;
	}
	auto changed = false;
	for (const auto values : { &_messageChanges, &_selfPinChanges }) {
		const auto old = values->find(oldId);
		if (old != values->end()) {
			auto value = old->second;
			value.clock = 0;
			value.device = "local";
			values->erase(old);
			values->try_emplace(FullMsgId(oldId.peer, newId), std::move(value));
			changed = true;
		}
	}
	if (changed) {
		save();
		_changes.fire({});
	}
}

bool PrivateSpace::selfPinned(FullMsgId id) const {
	if (!messageStateReady()) {
		return false;
	}
	const auto local = _selfPinChanges.find(id);
	if (local != _selfPinChanges.end()) {
		return local->second.state == "present";
	}
	const auto peer = Sync::CanonicalPeerId(id.peer);
	return peer && _syncProjection
		&& SyncedSelfPinned(_syncProjection->content, *peer, id.msg.bare);
}

void PrivateSpace::forgetPrivateMessages(PeerId peer) {
	for (const auto values : { &_messageChanges, &_selfPinChanges }) {
		for (auto i = values->begin(); i != values->end();) {
			if (i->first.peer == peer) i = values->erase(i);
			else ++i;
		}
	}
	save();
}

void PrivateSpace::recordSelfPin(FullMsgId id, bool pinned) {
	if (!hidden(id.peer) || !allowsMessage(id)) {
		return;
	}
	bindPrivateMessageIntents();
	_selfPinChanges[id] = { pinned ? "present" : "removed", 0, "local", {} };
	save();
	_changes.fire({});
}

bool PrivateSpace::privateSearch(PeerId peer) const {
	const auto local = _searchChanges.find(peer);
	if (local != _searchChanges.end()) {
		return local->second.state != "removed";
	}
	const auto id = Sync::CanonicalPeerId(peer);
	if (!id || !_syncProjection) {
		return false;
	}
	const auto &values = _syncProjection->content.privateSearchDialogIds;
	const auto i = values.find(*Sync::CanonicalPeerKey(*id));
	return i != values.end() && i->second.state != "removed";
}

bool PrivateSpace::allowsRecentSearch(PeerId peer) const {
	return allowsPeer(peer) && (active() || !privateSearch(peer));
}

void PrivateSpace::recordSearch(PeerId peer) {
	if (!configured() || !messageStateReady() || !Sync::CanonicalPeerId(peer)) {
		return;
	}
	if (privateSearch(peer) == active()) return;
	bindPrivateMessageIntents();
	_searchChanges[peer] = { active() ? "present" : "removed", 0, "local", {} };
	save();
	crl::on_main(_session, [=] { _changes.fire({}); });
}

void PrivateSpace::initPrivateMessages() {
	const auto wasActive = _lifetime.make_state<bool>(active());
	changes() | rpl::on_next([=] {
		const auto entered = active() && !*wasActive;
		*wasActive = active();
		if (entered) {
			crl::on_main(_session, [=] {
				if (active()) ShowPendingMessagesDecision(_session);
			});
		}
		if (!_syncEnabled || _messageFlushScheduled) {
			return;
		}
		_messageFlushScheduled = true;
		crl::on_main(_session, [=] {
			_messageFlushScheduled = false;
			flushPrivateMessages();
		});
	}, _lifetime);
}

std::vector<FullMsgId> PrivateSpace::pendingMessages() const {
	if (!active()) return {};
	auto peers = std::set<PeerId>();
	for (const auto &[id, value] : _messageChanges) peers.emplace(id.peer);
	for (const auto peer : hiddenPeersForManagement()) peers.emplace(peer);
	auto result = std::vector<FullMsgId>();
	for (const auto peer : peers) {
		for (const auto id : publicMessages(peer)) {
			if (messageState(id) == MessageState::Pending) result.push_back(id);
		}
	}
	return result;
}

void PrivateSpace::reconcilePrivateMessages() {
	if (!_syncProjection) {
		return;
	}
	bindPrivateMessageIntents();
	for (const auto values : { &_messageChanges, &_selfPinChanges }) {
		for (auto i = values->begin(); i != values->end();) {
			if (!hidden(i->first.peer)) i = values->erase(i);
			else ++i;
		}
	}
	const auto acknowledged = [&](auto &values, const auto &lookup) {
		for (auto i = values.begin(); i != values.end();) {
			const auto remote = lookup(i->first);
			if (i->second.clock > 0 && remote
				&& remote->clock >= i->second.clock) {
				i = values.erase(i);
			} else {
				++i;
			}
		}
	};
	const auto perMessage = [&](FullMsgId id, bool pin) -> std::optional<Sync::Register> {
		const auto peer = Sync::CanonicalPeerId(id.peer);
		if (!peer) return std::nullopt;
		const auto chat = _syncProjection->content.perChat.find(*Sync::CanonicalPeerKey(*peer));
		if (chat == _syncProjection->content.perChat.end()) return std::nullopt;
		const auto &values = pin ? chat->second.selfPinned : chat->second.messageState;
		const auto i = values.find(std::to_string(id.msg.bare));
		if (i == values.end() || chat->second.clearedAtClock > i->second.clock) {
			return Sync::Register{ "removed", chat->second.clearedAtClock, "clear", {} };
		}
		return i->second;
	};
	acknowledged(_messageChanges, [&](FullMsgId id) { return perMessage(id, false); });
	acknowledged(_selfPinChanges, [&](FullMsgId id) { return perMessage(id, true); });
	acknowledged(_searchChanges, [&](PeerId peer) -> const Sync::Register* {
		const auto id = Sync::CanonicalPeerId(peer);
		if (!id) return nullptr;
		const auto &values = _syncProjection->content.privateSearchDialogIds;
		const auto i = values.find(*Sync::CanonicalPeerKey(*id));
		return i == values.end() ? nullptr : &i->second;
	});
	save();
}

void PrivateSpace::bindPrivateMessageIntents() {
	if (!_syncEnabled || !_syncProjection) return;
	if (_messageEpochKnown && _messagePinEpoch != _syncProjection->content.pin) {
		invalidatePrivateMessageIntents();
	}
	_messageEpochKnown = true;
	_messagePinEpoch = _syncProjection->content.pin;
}

void PrivateSpace::invalidatePrivateMessageIntents() {
	const auto keepProtection = [](auto &values, const char *state) {
		for (auto i = values.begin(); i != values.end();) {
			if (i->second.state == state) {
				i->second.clock = kLocalOnlyClock;
				i->second.device = "local-only";
				++i;
			} else {
				i = values.erase(i);
			}
		}
	};
	keepProtection(_messageChanges, "hidden");
	keepProtection(_searchChanges, "present");
	_selfPinChanges.clear();
	save();
}

void PrivateSpace::flushPrivateMessages() {
	if (!PrivateAccountContentAllowed(_session)
		|| !_syncEnabled || !_sync || !_sync->projection()) {
		return;
	}
	bindPrivateMessageIntents();
	const auto messageReady = [&](const auto &entry) {
		return entry.second.clock == 0 && IsServerMsgId(entry.first.msg)
			&& (active() || entry.second.state == "pending");
	};
	const auto otherReady = [](const auto &entry) { return entry.second.clock == 0; };
	if (!ranges::any_of(_messageChanges, messageReady)
		&& !ranges::any_of(_selfPinChanges, [&](const auto &entry) {
			return otherReady(entry) && IsServerMsgId(entry.first.msg);
		}) && !ranges::any_of(_searchChanges, otherReady)) {
		return;
	}
	const auto messages = _messageChanges;
	const auto pins = _selfPinChanges;
	const auto searches = _searchChanges;
	const auto weak = base::make_weak(_session);
	const auto submitted = syncMutate([&](auto &, auto &content, std::int64_t clock) {
		for (auto &[id, value] : _messageChanges) {
			if (!messageReady(std::pair(id, value))) continue;
			const auto peer = Sync::CanonicalPeerId(id.peer);
			if (!peer) continue;
			value.clock = clock;
			value.device = _syncDevice.toStdString();
			content.perChat[*Sync::CanonicalPeerKey(*peer)].messageState[std::to_string(id.msg.bare)] = value;
		}
		for (auto &[id, value] : _selfPinChanges) {
			if (value.clock || !IsServerMsgId(id.msg)) continue;
			const auto peer = Sync::CanonicalPeerId(id.peer);
			if (!peer) continue;
			value.clock = clock;
			value.device = _syncDevice.toStdString();
			content.perChat[*Sync::CanonicalPeerKey(*peer)].selfPinned[std::to_string(id.msg.bare)] = value;
		}
		for (auto &[peer, value] : _searchChanges) {
			if (value.clock) continue;
			const auto id = Sync::CanonicalPeerId(peer);
			if (!id) continue;
			value.clock = clock;
			value.device = _syncDevice.toStdString();
			content.privateSearchDialogIds[*Sync::CanonicalPeerKey(*id)] = value;
		}
	});
	if (!weak) return;
	if (!submitted) {
		_messageChanges = messages;
		_selfPinChanges = pins;
		_searchChanges = searches;
	}
	save();
}

QByteArray PrivateSpace::serializePrivateMessages() const {
	auto bytes = QByteArray();
	auto stream = QDataStream(&bytes, QIODevice::WriteOnly);
	stream.setVersion(QDataStream::Qt_5_1);
	auto epoch = Sync::ContentBlob();
	epoch.pin = _messagePinEpoch;
	const auto encoded = Sync::EncodeContentBlob(epoch);
	stream << qint32(_messageEpochKnown ? 1 : 0)
		<< (encoded ? QByteArray(encoded->data(), encoded->size()) : QByteArray());
	const auto write = [&](const auto &values) {
		stream << qint32(values.size());
		for (const auto &[id, value] : values) {
			if constexpr (std::is_same_v<std::decay_t<decltype(id)>, PeerId>) {
				stream << quint64(id.value);
			} else {
				stream << quint64(id.peer.value) << qint64(id.msg.bare);
			}
			stream << QString::fromStdString(value.state)
				<< qint64(value.clock) << QString::fromStdString(value.device);
		}
	};
	write(_messageChanges);
	write(_selfPinChanges);
	write(_searchChanges);
	return bytes;
}

bool PrivateSpace::restorePrivateMessages(const QByteArray &bytes) {
	if (bytes.size() > 2 * 1024 * 1024) return false;
	auto stream = QDataStream(bytes);
	stream.setVersion(QDataStream::Qt_5_1);
	auto known = qint32();
	auto encoded = QByteArray();
	stream >> known >> encoded;
	const auto epoch = Sync::ReadContentBlob(std::string_view(encoded.constData(), encoded.size()));
	if ((known != 0 && known != 1) || !epoch.blob) return false;
	_messageEpochKnown = known;
	_messagePinEpoch = epoch.blob->pin;
	auto total = 0;
	const auto read = [&](auto &values, bool messages) {
		auto count = qint32();
		stream >> count;
		if (count < 0 || count > kMaximumEntries - total) return false;
		total += count;
		for (auto index = 0; index != count; ++index) {
			auto peer = quint64();
			auto message = qint64();
			auto state = QString();
			auto clock = qint64();
			auto device = QString();
			stream >> peer;
			using Key = typename std::decay_t<decltype(values)>::key_type;
			if constexpr (std::is_same_v<Key, FullMsgId>) stream >> message;
			stream >> state >> clock >> device;
			if (!Sync::CanonicalPeerId(PeerId(peer)) || clock < 0
				|| device.isEmpty() || device.size() > 256
				|| (messages ? (state != u"hidden"_q && state != u"exposed"_q && state != u"pending"_q)
					: (state != u"present"_q && state != u"removed"_q))) return false;
			const auto value = Sync::Register{ state.toStdString(), clock, device.toStdString(), {} };
			if constexpr (std::is_same_v<Key, FullMsgId>) {
				const auto id = FullMsgId(PeerId(peer), MsgId(message));
				if (!ValidId(id) || !values.emplace(id, value).second) return false;
			} else {
				if (!values.emplace(PeerId(peer), value).second) return false;
			}
		}
		return true;
	};
	return read(_messageChanges, true) && read(_selfPinChanges, false)
		&& read(_searchChanges, false) && stream.status() == QDataStream::Ok && stream.atEnd();
}

} // namespace Leemen
