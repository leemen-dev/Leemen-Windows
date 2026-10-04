#include "leemen/sync_identifiers.h"

#include <charconv>
#include <limits>
#include <system_error>

namespace Leemen::Sync {
namespace {

constexpr auto kAndroidSyntheticMask = std::uint64_t(0x6000000000000000);

bool IsCanonicalPeerId(std::int64_t value) {
	return value
		&& value != std::numeric_limits<std::int64_t>::min()
		&& (value < 0 || !(std::uint64_t(value) & kAndroidSyntheticMask));
}

std::optional<std::int64_t> ParseDecimal(std::string_view key) {
	if (key.empty() || key.size() > 20) {
		return std::nullopt;
	}
	auto value = std::int64_t();
	const auto end = key.data() + key.size();
	const auto result = std::from_chars(key.data(), end, value);
	if (result.ec != std::errc()
		|| result.ptr != end
		|| std::to_string(value) != key) {
		return std::nullopt;
	}
	return value;
}

bool IsCloudMessageId(std::int64_t value) {
	return value > 0 && value <= std::numeric_limits<std::int32_t>::max();
}

} // namespace

std::optional<std::int64_t> EncodeCanonicalPeerId(
		std::int64_t rawId,
		CloudPeerKind kind) {
	if (rawId <= 0) {
		return std::nullopt;
	}
	switch (kind) {
	case CloudPeerKind::User:
		return IsCanonicalPeerId(rawId)
			? std::make_optional(rawId)
			: std::nullopt;
	case CloudPeerKind::Group:
	case CloudPeerKind::Channel:
		return -rawId;
	}
	return std::nullopt;
}

std::optional<std::int64_t> DecodeCanonicalPeerId(
		std::int64_t canonicalId,
		CloudPeerKind kind) {
	if (!IsCanonicalPeerId(canonicalId)) {
		return std::nullopt;
	}
	switch (kind) {
	case CloudPeerKind::User:
		if (canonicalId > 0) {
			return canonicalId;
		}
		break;
	case CloudPeerKind::Group:
	case CloudPeerKind::Channel:
		if (canonicalId < 0) {
			return -canonicalId;
		}
		break;
	}
	return std::nullopt;
}

std::optional<std::int64_t> ParseCanonicalPeerKey(std::string_view key) {
	const auto value = ParseDecimal(key);
	return (value && IsCanonicalPeerId(*value)) ? value : std::nullopt;
}

std::optional<std::string> CanonicalPeerKey(std::int64_t canonicalId) {
	return IsCanonicalPeerId(canonicalId)
		? std::make_optional(std::to_string(canonicalId))
		: std::nullopt;
}

std::optional<std::int32_t> ParseCloudMessageKey(std::string_view key) {
	const auto value = ParseDecimal(key);
	return (value && IsCloudMessageId(*value))
		? std::make_optional(std::int32_t(*value))
		: std::nullopt;
}

std::optional<std::string> CloudMessageKey(std::int64_t messageId) {
	return IsCloudMessageId(messageId)
		? std::make_optional(std::to_string(messageId))
		: std::nullopt;
}

} // namespace Leemen::Sync
