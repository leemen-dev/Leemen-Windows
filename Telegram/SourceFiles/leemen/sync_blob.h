#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace Leemen::Sync {

inline constexpr auto kBlobSchemaVersion = 2;
inline constexpr auto kMaxBlobPlaintextBytes = std::size_t(256 * 1024 - 16);

struct JsonNumber {
	std::string token;
	bool operator==(const JsonNumber &) const = default;
};

struct JsonValue {
	using Array = std::vector<JsonValue>;
	using Object = std::map<std::string, JsonValue>;
	std::variant<std::nullptr_t, bool, JsonNumber, std::string, Array, Object>
		value = nullptr;
	bool operator==(const JsonValue &) const = default;
};

enum class JsonBudget { Remote, LocalCheckpoint };

struct JsonLimits {
	std::size_t maxBytes = kMaxBlobPlaintextBytes;
	std::size_t maxDepth = 64;
	std::size_t maxNodes = 131072;
	JsonBudget budget = JsonBudget::Remote;
};

struct JsonRead {
	std::optional<JsonValue> value;
	std::string error;
};

[[nodiscard]] JsonRead ParseJson(std::string_view text, JsonLimits limits = {});
[[nodiscard]] std::optional<std::string> EncodeJson(
	const JsonValue &value,
	JsonLimits limits = {});
[[nodiscard]] std::optional<std::int64_t> ExactInt64(const JsonValue &value);

using UnknownFields = JsonValue::Object;

struct Register {
	std::string state;
	std::int64_t clock = 0;
	std::string device;
	UnknownFields unknownFields;
	bool operator==(const Register &) const = default;
};

struct IntRegister {
	std::int64_t value = 0;
	std::int64_t clock = 0;
	std::string device;
	UnknownFields unknownFields;
	bool operator==(const IntRegister &) const = default;
};

struct BoolRegister {
	bool value = false;
	std::int64_t clock = 0;
	std::string device;
	UnknownFields unknownFields;
	bool operator==(const BoolRegister &) const = default;
};

struct PinRegister {
	std::string state;
	std::optional<std::string> hash;
	std::optional<std::string> salt;
	std::optional<std::string> kdf;
	std::int64_t clock = 0;
	std::string device;
	UnknownFields unknownFields;
	bool operator==(const PinRegister &) const = default;
};

struct PerChat {
	std::int64_t clearedAtClock = 0;
	std::map<std::string, Register> messageState;
	std::map<std::string, Register> selfPinned;
	UnknownFields unknownFields;
	bool operator==(const PerChat &) const = default;
};

struct SpaceSettings {
	std::optional<IntRegister> pinTimeoutMinutes;
	std::optional<BoolRegister> allowScreenshots;
	UnknownFields unknownFields;
	bool operator==(const SpaceSettings &) const = default;
};

struct FilterBlob {
	std::int64_t lamport = 0;
	std::map<std::string, Register> hiddenChatIds;
	std::vector<std::string> chatsOffModeVisible;
	std::optional<std::string> padding;
	UnknownFields unknownFields;
	bool operator==(const FilterBlob &) const = default;
};

struct ContentBlob {
	std::int64_t lamport = 0;
	std::map<std::string, PerChat> perChat;
	std::map<std::string, Register> privateSearchDialogIds;
	SpaceSettings settings;
	std::optional<PinRegister> pin;
	std::optional<JsonValue::Object> platform;
	UnknownFields unknownFields;
	bool operator==(const ContentBlob &) const = default;
};

enum class BlobReadStatus {
	Decoded,
	Absent,
	Invalid,
	UnsupportedSchema,
};

template <typename Blob>
struct BlobRead {
	BlobReadStatus status = BlobReadStatus::Invalid;
	std::optional<Blob> blob;
	std::string error;
};

// nullopt means transport-confirmed absence; empty or malformed bytes are invalid.
[[nodiscard]] BlobRead<FilterBlob> ReadFilterBlob(
	std::optional<std::string_view> plaintext);
[[nodiscard]] BlobRead<ContentBlob> ReadContentBlob(
	std::optional<std::string_view> plaintext);
[[nodiscard]] std::optional<std::string> EncodeFilterBlob(
	const FilterBlob &blob);
[[nodiscard]] std::optional<std::string> EncodeContentBlob(
	const ContentBlob &blob);
[[nodiscard]] FilterBlob MergeFilter(
	const FilterBlob &left,
	const FilterBlob &right);
[[nodiscard]] ContentBlob MergeContent(
	const ContentBlob &left,
	const ContentBlob &right);
void RecomputeOffModeVisible(FilterBlob &filter, const ContentBlob &content);
[[nodiscard]] bool ProtectsMembership(const Register &value);
[[nodiscard]] bool MessageVisible(const Register &value, const PerChat &chat);
[[nodiscard]] std::optional<std::int64_t> NextLamport(
	FilterBlob &filter,
	ContentBlob &content);

} // namespace Leemen::Sync
