#pragma once

#include "leemen/sync_blob.h"
#include "leemen/sync_identifiers.h"

namespace Leemen::Sync {

struct LocalIntentStamp {
	std::int64_t clock = 0;
	std::string device;
	bool operator==(const LocalIntentStamp &) const = default;
};

[[nodiscard]] inline bool IsConfirmedLocalRemoval(
		const FilterBlob &filter,
		std::int64_t peer,
		const LocalIntentStamp &stamp) {
	const auto key = CanonicalPeerKey(peer);
	if (!key || stamp.clock <= 0 || stamp.device.empty()) {
		return false;
	}
	const auto i = filter.hiddenChatIds.find(*key);
	return i != filter.hiddenChatIds.end()
		&& i->second.state == "removed"
		&& i->second.clock == stamp.clock
		&& i->second.device == stamp.device;
}

[[nodiscard]] inline bool IsConfirmedLocalDisable(
		const FilterBlob &filter,
		const ContentBlob &content,
		const LocalIntentStamp &stamp) {
	if (!content.pin || stamp.clock <= 0 || stamp.device.empty()
		|| content.pin->state != "none"
		|| content.pin->clock != stamp.clock
		|| content.pin->device != stamp.device) {
		return false;
	}
	for (const auto &[key, value] : filter.hiddenChatIds) {
		if (ProtectsMembership(value)) {
			return false;
		}
	}
	return true;
}

} // namespace Leemen::Sync
