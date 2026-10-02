#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Leemen::Sync::Realtime {

inline constexpr auto kMaxMessageBytes = std::size_t(64 * 1024);
inline constexpr auto kMaxUpgradeBytes = std::size_t(8 * 1024);
inline constexpr auto kMaxFeedBytes = kMaxMessageBytes * 2 + 16;

enum class Opcode : unsigned char { Text = 1, Close = 8, Ping = 9, Pong = 10 };
struct Frame { Opcode opcode = Opcode::Text; std::vector<unsigned char> payload; };

class Decoder {
public:
	[[nodiscard]] std::optional<std::vector<Frame>> feed(std::span<const unsigned char> bytes);
	void clear();

private:
	std::vector<unsigned char> _buffer;
	std::vector<unsigned char> _fragments;
	bool _fragmented = false;
	bool _failed = false;
	bool _closed = false;

};

[[nodiscard]] bool ValidUtf8(std::span<const unsigned char> bytes);
[[nodiscard]] std::optional<std::string> UpgradeAccept(std::string_view clientKey);
[[nodiscard]] bool ValidUpgrade(std::string_view header, std::string_view expectedAccept);
[[nodiscard]] std::optional<std::vector<unsigned char>> ClientFrame(
	Opcode opcode,
	std::span<const unsigned char> payload,
	std::array<unsigned char, 4> mask);
[[nodiscard]] std::optional<std::string> Topic(std::string_view syncAccountUuid);
[[nodiscard]] std::optional<std::string> Join(
	std::string_view syncAccountUuid,
	std::string_view publicKey,
	std::string_view reference);
[[nodiscard]] std::optional<std::string> Heartbeat(std::string_view reference);

enum class Event { Ignore, Malformed, Joined, ChannelClosed, HeartbeatAck, Changed };
[[nodiscard]] Event Classify(
	std::string_view json,
	std::string_view topic,
	std::string_view joinReference,
	std::string_view heartbeatReference,
	bool joined);

} // namespace Leemen::Sync::Realtime
