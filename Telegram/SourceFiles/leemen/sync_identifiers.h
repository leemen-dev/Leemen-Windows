#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace Leemen::Sync {

enum class CloudPeerKind {
	User,
	Group,
	Channel,
};

// rawId is the Telegram cloud id, never Desktop's tagged PeerId::value.
// Negative canonical ids need caller-provided group/channel kind to decode.
[[nodiscard]] std::optional<std::int64_t> EncodeCanonicalPeerId(
	std::int64_t rawId,
	CloudPeerKind kind);
[[nodiscard]] std::optional<std::int64_t> DecodeCanonicalPeerId(
	std::int64_t canonicalId,
	CloudPeerKind kind);
[[nodiscard]] std::optional<std::int64_t> ParseCanonicalPeerKey(
	std::string_view key);
[[nodiscard]] std::optional<std::string> CanonicalPeerKey(
	std::int64_t canonicalId);
[[nodiscard]] std::optional<std::int32_t> ParseCloudMessageKey(
	std::string_view key);
[[nodiscard]] std::optional<std::string> CloudMessageKey(
	std::int64_t messageId);

} // namespace Leemen::Sync
