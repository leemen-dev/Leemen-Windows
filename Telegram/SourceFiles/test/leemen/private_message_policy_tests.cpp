#include "leemen/private_message_policy.h"
#include "leemen/public_media_policy.h"

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
	const auto selected = PublicMediaSelection{ 7, 42, 19, 901, PublicMediaKind::Photo, 1 };
	Check(AllowsPublicMedia(selected, selected, true),
		"the authorized exact attachment was denied");
	Check(!AllowsPublicMedia(selected, selected, false),
		"revoked attachment authorization survived");
	for (auto index = 0; index != 5; ++index) {
		auto target = selected;
		switch (index) {
		case 0: ++target.session; break;
		case 1: ++target.peer; break;
		case 2: ++target.message; break;
		case 3: ++target.media; break;
		case 4: target.kind = PublicMediaKind::Document; break;
		}
		Check(!AllowsPublicMedia(selected, target, true),
			"another session, chat, message, media or kind inherited attachment authorization");
	}
	auto reopened = selected;
	++reopened.request;
	Check(!AllowsPublicMedia(selected, reopened, true),
		"an old callback survived close and reopening the exact same attachment");
	Check(AllowsPublicMedia(reopened, reopened, true),
		"a newly authorized opening of the same attachment was denied");
	for (auto index = 0; index != 7; ++index) {
		auto invalid = selected;
		switch (index) {
		case 0: invalid.session = 0; break;
		case 1: invalid.peer = 0; break;
		case 2: invalid.message = 0; break;
		case 3: invalid.media = 0; break;
		case 4: invalid.kind = PublicMediaKind::None; break;
		case 5: invalid.kind = static_cast<PublicMediaKind>(99); break;
		case 6: invalid.request = 0; break;
		}
		Check(!AllowsPublicMedia(invalid, invalid, true),
			"an incomplete or unknown attachment selection was accepted");
	}
	auto pending = selected;
	pending.message = -20;
	pending.kind = PublicMediaKind::Document;
	Check(AllowsPublicMedia(pending, pending, true),
		"an authorized pending local attachment was denied");
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
