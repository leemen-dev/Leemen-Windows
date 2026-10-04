#pragma once

#include "leemen/private_space_state.h"
#include "leemen/sync_blob.h"
#include "leemen/sync_identifiers.h"

namespace Leemen {

[[nodiscard]] inline bool PrivateSearchOnly(
		const Sync::ContentBlob *content,
		std::int64_t peer,
		const Sync::Register *local = nullptr) {
	const auto key = Sync::CanonicalPeerKey(peer);
	if (!key) {
		return false;
	}
	if (local) {
		return local->state != "removed";
	}
	if (!content) {
		return false;
	}
	const auto value = content->privateSearchDialogIds.find(*key);
	return value != content->privateSearchDialogIds.end()
		&& value->second.state != "removed";
}

[[nodiscard]] inline bool VisibleOwnPinService(
		bool outgoing,
		bool sameChat,
		MessageState target) {
	return outgoing && sameChat
		&& (target == MessageState::Exposed || target == MessageState::Pending);
}

[[nodiscard]] inline MessageState SyncedMessageState(
		const Sync::ContentBlob &content,
		std::int64_t peer,
		std::int64_t message) {
	const auto key = Sync::CanonicalPeerKey(peer);
	if (!key || !Sync::ParseCloudMessageKey(std::to_string(message))) {
		return MessageState::Hidden;
	}
	const auto chat = content.perChat.find(*key);
	if (chat == content.perChat.end()) {
		return MessageState::Hidden;
	}
	const auto value = chat->second.messageState.find(std::to_string(message));
	if (value == chat->second.messageState.end()
		|| !Sync::MessageVisible(value->second, chat->second)) {
		return MessageState::Hidden;
	}
	return value->second.state == "pending"
		? MessageState::Pending : MessageState::Exposed;
}

[[nodiscard]] inline bool SyncedSelfPinned(
		const Sync::ContentBlob &content,
		std::int64_t peer,
		std::int64_t message) {
	const auto key = Sync::CanonicalPeerKey(peer);
	if (!key || !Sync::ParseCloudMessageKey(std::to_string(message))) {
		return false;
	}
	const auto chat = content.perChat.find(*key);
	if (chat == content.perChat.end()) {
		return false;
	}
	const auto value = chat->second.selfPinned.find(std::to_string(message));
	return value != chat->second.selfPinned.end()
		&& value->second.state == "present"
		&& value->second.clock >= chat->second.clearedAtClock;
}

} // namespace Leemen
