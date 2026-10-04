#pragma once

#include "leemen/sync_backend.h"
#include "leemen/sync_coordinator.h"

namespace Leemen::Sync {

enum class LocalResetState { None, Pending, Confirmed };

struct SessionSnapshot {
	std::uint64_t telegramUserId = 0;
	Backend::Generation generation;
	bool maximum = false;
	std::optional<std::string> keyFingerprint;
	LocalResetState reset = LocalResetState::None;
	SyncCheckpoint checkpoint;
	bool accountDeletePending = false;
};

[[nodiscard]] std::optional<std::string> EncodeSessionSnapshot(
	const SessionSnapshot &snapshot);
[[nodiscard]] std::optional<SessionSnapshot> ReadSessionSnapshot(
	std::string_view serialized,
	std::uint64_t expectedTelegramUserId);

} // namespace Leemen::Sync
