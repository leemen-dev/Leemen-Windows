#include "leemen/private_message_policy.h"

#include <cstdlib>
#include <iostream>

namespace {

void Check(bool value, const char *message) {
	if (!value) {
		std::cerr << message << '\n';
		std::exit(EXIT_FAILURE);
	}
}

} // namespace

int main() {
	using namespace Leemen;
	Check(VisibleOwnPinService(true, true, MessageState::Exposed),
		"own pin of an exposed message disappeared");
	Check(VisibleOwnPinService(true, true, MessageState::Pending),
		"own pin of a pending message disappeared");
	Check(!VisibleOwnPinService(false, true, MessageState::Exposed),
		"another participant's pin became visible");
	Check(!VisibleOwnPinService(true, true, MessageState::Hidden),
		"own pin revealed a hidden target");
	Check(!VisibleOwnPinService(true, false, MessageState::Exposed),
		"cross-chat reply acquired pin visibility");
	Check(!VisibleOwnPinService(true, true, static_cast<MessageState>(99)),
		"unknown target state acquired pin visibility");
	auto content = Sync::ContentBlob();
	Check(SyncedMessageState(content, 42, 1) == MessageState::Hidden,
		"an unknown message became public");
	auto &chat = content.perChat["42"];
	chat.messageState["1"] = { "exposed", 4, "android", {} };
	chat.messageState["2"] = { "pending", 5, "android", {} };
	chat.messageState["3"] = { "future-state", 6, "android", {} };
	Check(SyncedMessageState(content, 42, 1) == MessageState::Exposed,
		"exposed message was not projected");
	Check(SyncedMessageState(content, 42, 2) == MessageState::Pending,
		"pending message lost provenance");
	Check(SyncedMessageState(content, 42, 3) == MessageState::Hidden,
		"unknown state was treated as public");
	Check(SyncedMessageState(content, 43, 1) == MessageState::Hidden,
		"same message id in another chat inherited exposure");
	Check(SyncedMessageState(content, 42, -1) == MessageState::Hidden,
		"a local placeholder was read from synchronized cloud state");
	Check(SyncedMessageState(content, 0, 1) == MessageState::Hidden,
		"invalid peer became public");
	chat.clearedAtClock = 5;
	Check(SyncedMessageState(content, 42, 1) == MessageState::Hidden,
		"removed chat metadata resurrected exposure");
	Check(SyncedMessageState(content, 42, 2) == MessageState::Pending,
		"same-clock newly added state was discarded at clear boundary");
	chat.selfPinned["1"] = { "present", 4, "android", {} };
	chat.selfPinned["2"] = { "present", 5, "android", {} };
	Check(!SyncedSelfPinned(content, 42, 1), "old self pin survived a clear");
	Check(SyncedSelfPinned(content, 42, 2), "new self pin was not projected");
	chat.selfPinned["2"].state = "removed";
	Check(!SyncedSelfPinned(content, 42, 2), "removed self pin returned");
	chat.selfPinned["2"].state = "future-state";
	Check(!SyncedSelfPinned(content, 42, 2), "unknown provenance enabled a pin");
	const auto encoded = Sync::EncodeContentBlob(content);
	Check(encoded.has_value(), "message state did not encode");
	const auto decoded = Sync::ReadContentBlob(*encoded);
	Check(decoded.blob && SyncedMessageState(*decoded.blob, 42, 2) == MessageState::Pending,
		"message projection changed across persistence");
	std::cout << "Private message policy tests passed.\n";
}
