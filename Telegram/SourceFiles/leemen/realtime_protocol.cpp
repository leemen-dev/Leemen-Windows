#include "leemen/realtime_protocol.h"

#include "leemen/sync_backend.h"
#include "leemen/sync_blob.h"

#include <openssl/evp.h>
#include <algorithm>
#include <limits>

namespace Leemen::Sync::Realtime {
namespace {

bool ValidClose(std::span<const unsigned char> bytes) {
	if (bytes.empty()) return true;
	if (bytes.size() == 1) return false;
	const auto code = (unsigned(bytes[0]) << 8) | bytes[1];
	return (((code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006)
		|| (code >= 3000 && code <= 4999)) && ValidUtf8(bytes.subspan(2)));
}

std::string Lower(std::string_view text) {
	auto result = std::string(text);
	for (auto &c : result) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
	return result;
}

std::string_view Trim(std::string_view text) {
	while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
	while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
	return text;
}

bool HasToken(std::string_view value, std::string_view token) {
	while (!value.empty()) {
		const auto comma = value.find(',');
		if (Lower(Trim(value.substr(0, comma))) == token) return true;
		if (comma == std::string_view::npos) return false;
		value.remove_prefix(comma + 1);
	}
	return false;
}

bool ValidReference(std::string_view value) {
	return !value.empty() && value.size() <= 20 && value.front() >= '1' && value.front() <= '9'
		&& std::ranges::all_of(value, [](char c) { return c >= '0' && c <= '9'; });
}

const JsonValue *Field(const JsonValue &value, const char *key) {
	const auto object = std::get_if<JsonValue::Object>(&value.value);
	if (!object) return nullptr;
	const auto i = object->find(key);
	return i == object->end() ? nullptr : &i->second;
}

std::string_view String(const JsonValue *value) {
	const auto text = value ? std::get_if<std::string>(&value->value) : nullptr;
	return text ? std::string_view(*text) : std::string_view();
}

} // namespace

bool ValidUtf8(std::span<const unsigned char> bytes) {
	for (auto i = std::size_t(0); i < bytes.size();) {
		const auto first = bytes[i++];
		if (first < 0x80) continue;
		const auto count = first >= 0xC2 && first <= 0xDF ? 1
			: first >= 0xE0 && first <= 0xEF ? 2 : first >= 0xF0 && first <= 0xF4 ? 3 : -1;
		if (count < 0 || bytes.size() - i < std::size_t(count)) return false;
		auto point = std::uint32_t(first & (0x7F >> (count + 1)));
		for (auto j = 0; j < count; ++j) {
			const auto next = bytes[i++];
			if ((next & 0xC0) != 0x80) return false;
			point = (point << 6) | (next & 0x3F);
		}
		const auto minimum = count == 1 ? 0x80U : count == 2 ? 0x800U : 0x10000U;
		if (point < minimum || point > 0x10FFFF || (point >= 0xD800 && point <= 0xDFFF)) return false;
	}
	return true;
}

std::optional<std::vector<Frame>> Decoder::feed(std::span<const unsigned char> bytes) {
	if (_failed || _closed || bytes.size() > kMaxFeedBytes || _buffer.size() > kMaxFeedBytes - bytes.size()) {
		_failed = true;
		return std::nullopt;
	}
	_buffer.insert(_buffer.end(), bytes.begin(), bytes.end());
	auto result = std::vector<Frame>();
	auto offset = std::size_t(0);
	auto frames = std::size_t(0);
	const auto fail = [&]() -> std::optional<std::vector<Frame>> {
		_failed = true;
		_buffer.clear();
		_fragments.clear();
		return std::nullopt;
	};
	while (_buffer.size() - offset >= 2) {
		const auto input = std::span(_buffer).subspan(offset);
		const auto final = (input[0] & 0x80) != 0;
		const auto opcode = input[0] & 0x0F;
		const auto control = opcode >= 8;
		auto size = std::uint64_t(input[1] & 0x7F);
		auto header = std::size_t(2);
		if ((input[0] & 0x70) || (input[1] & 0x80)
			|| (opcode != 0 && opcode != 1 && opcode != 8 && opcode != 9 && opcode != 10)
			|| (control && (!final || size > 125))) return fail();
		if (size == 126 || size == 127) {
			header += size == 126 ? 2 : 8;
			if (input.size() < header) break;
			const auto marker = size;
			size = 0;
			for (auto i = std::size_t(2); i < header; ++i) size = (size << 8) | input[i];
			if ((marker == 126 && size < 126) || (marker == 127 && (size < 65536 || (input[2] & 0x80)))) return fail();
		}
		if (size > kMaxMessageBytes || (!control && size > kMaxMessageBytes - _fragments.size())) return fail();
		if (size > input.size() - header) break;
		if (++frames > 256) return fail();
		const auto payload = input.subspan(header, std::size_t(size));
		offset += header + std::size_t(size);
		if (control) {
			if (opcode == 8 && !ValidClose(payload)) return fail();
			result.push_back({ Opcode(opcode), { payload.begin(), payload.end() } });
			if (opcode == 8) { _closed = true; break; }
		} else {
			if ((opcode == 0 && !_fragmented) || (opcode == 1 && _fragmented)) return fail();
			_fragments.insert(_fragments.end(), payload.begin(), payload.end());
			_fragmented = !final;
			if (final) {
				if (!ValidUtf8(_fragments)) return fail();
				result.push_back({ Opcode::Text, std::move(_fragments) });
				_fragments.clear();
			}
		}
	}
	_buffer.erase(_buffer.begin(), _buffer.begin() + offset);
	if (_closed) _buffer.clear();
	return result;
}

void Decoder::clear() {
	_buffer.clear();
	_fragments.clear();
	_fragmented = _failed = _closed = false;
}

std::optional<std::string> UpgradeAccept(std::string_view clientKey) {
	if (clientKey.size() != 24 || clientKey.substr(22) != "=="
		|| std::string_view("AQgw").find(clientKey[21]) == std::string_view::npos
		|| !std::ranges::all_of(clientKey.substr(0, 22), [](char c) {
			return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
		})) return std::nullopt;
	const auto material = std::string(clientKey) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	auto digest = std::array<unsigned char, 20>();
	auto size = 0U;
	if (EVP_Digest(material.data(), material.size(), digest.data(), &size, EVP_sha1(), nullptr) != 1 || size != digest.size()) return std::nullopt;
	auto result = std::array<unsigned char, 29>();
	if (EVP_EncodeBlock(result.data(), digest.data(), int(digest.size())) != 28) return std::nullopt;
	return std::string(reinterpret_cast<const char*>(result.data()), 28);
}

bool ValidUpgrade(std::string_view header, std::string_view expectedAccept) {
	if (header.size() > kMaxUpgradeBytes || !header.ends_with("\r\n\r\n") || expectedAccept.size() != 28) return false;
	const auto first = header.find("\r\n");
	const auto status = header.substr(0, first);
	if (!(status == "HTTP/1.1 101" || status.starts_with("HTTP/1.1 101 "))) return false;
	if (std::ranges::any_of(status, [](unsigned char c) { return (c < 32 && c != '\t') || c == 127; })) return false;
	header.remove_prefix(first + 2);
	auto upgrade = false;
	auto connection = false;
	auto accept = false;
	while (header != "\r\n") {
		const auto next = header.find("\r\n");
		if (next == std::string_view::npos || next == 0) return false;
		const auto line = header.substr(0, next);
		const auto colon = line.find(':');
		if (colon == std::string_view::npos || !colon || line.front() == ' ' || line.front() == '\t') return false;
		const auto name = Lower(line.substr(0, colon));
		if (!std::ranges::all_of(name, [](char c) {
			return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
				|| std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
		})) return false;
		const auto value = Trim(line.substr(colon + 1));
		if (std::ranges::any_of(value, [](unsigned char c) { return (c < 32 && c != '\t') || c == 127; })) return false;
		if (name == "upgrade") upgrade = upgrade || HasToken(value, "websocket");
		else if (name == "connection") connection = connection || HasToken(value, "upgrade");
		else if (name == "sec-websocket-accept") {
			if (accept || value != expectedAccept) return false;
			accept = true;
		} else if (name == "sec-websocket-extensions" || name == "sec-websocket-protocol") return false;
		header.remove_prefix(next + 2);
	}
	return upgrade && connection && accept;
}

std::optional<std::vector<unsigned char>> ClientFrame(Opcode opcode, std::span<const unsigned char> payload, std::array<unsigned char, 4> mask) {
	const auto control = opcode != Opcode::Text;
	if (payload.size() > kMaxMessageBytes || (control && payload.size() > 125)
		|| (opcode == Opcode::Text && !ValidUtf8(payload)) || (opcode == Opcode::Close && !ValidClose(payload))
		|| (opcode != Opcode::Text && opcode != Opcode::Close && opcode != Opcode::Ping && opcode != Opcode::Pong)) return std::nullopt;
	auto result = std::vector<unsigned char>{ static_cast<unsigned char>(0x80 | static_cast<unsigned char>(opcode)) };
	if (payload.size() < 126) result.push_back(static_cast<unsigned char>(0x80 | payload.size()));
	else {
		result.push_back(payload.size() <= 65535 ? 0xFE : 0xFF);
		const auto count = payload.size() <= 65535 ? 2 : 8;
		for (auto i = count - 1; i >= 0; --i) result.push_back(static_cast<unsigned char>(std::uint64_t(payload.size()) >> (i * 8)));
	}
	result.insert(result.end(), mask.begin(), mask.end());
	for (auto i = std::size_t(0); i < payload.size(); ++i) result.push_back(payload[i] ^ mask[i % mask.size()]);
	return result;
}

std::optional<std::string> Topic(std::string_view syncAccountUuid) {
	const auto uuid = Backend::CanonicalUuid(syncAccountUuid);
	return uuid ? std::make_optional("realtime:sync:" + *uuid) : std::nullopt;
}

std::optional<std::string> Join(std::string_view syncAccountUuid, std::string_view publicKey, std::string_view reference) {
	const auto topic = Topic(syncAccountUuid);
	if (!topic || !ValidReference(reference) || publicKey.empty() || publicKey.size() > 4096) return std::nullopt;
	auto config = JsonValue::Object();
	config["broadcast"] = JsonValue{ JsonValue::Object{ { "ack", JsonValue{ false } }, { "self", JsonValue{ false } } } };
	config["presence"] = JsonValue{ JsonValue::Object{ { "enabled", JsonValue{ false } } } };
	config["postgres_changes"] = JsonValue{ JsonValue::Array() };
	config["private"] = JsonValue{ false };
	return EncodeJson(JsonValue{ JsonValue::Object{
		{ "topic", JsonValue{ *topic } }, { "event", JsonValue{ std::string("phx_join") } },
		{ "ref", JsonValue{ std::string(reference) } }, { "join_ref", JsonValue{ std::string(reference) } },
		{ "payload", JsonValue{ JsonValue::Object{ { "config", JsonValue{ std::move(config) } }, { "access_token", JsonValue{ std::string(publicKey) } } } } }
	} });
}

std::optional<std::string> Heartbeat(std::string_view reference) {
	if (!ValidReference(reference)) return std::nullopt;
	return "{\"topic\":\"phoenix\",\"event\":\"heartbeat\",\"payload\":{},\"ref\":\"" + std::string(reference) + "\"}";
}

Event Classify(std::string_view json, std::string_view topic, std::string_view joinReference, std::string_view heartbeatReference, bool joined) {
	if (json.size() > kMaxMessageBytes || !ValidUtf8({ reinterpret_cast<const unsigned char*>(json.data()), json.size() })) return Event::Malformed;
	const auto parsed = ParseJson(json, { kMaxMessageBytes, 8, 512 });
	if (!parsed.value || !std::holds_alternative<JsonValue::Object>(parsed.value->value)) return Event::Malformed;
	const auto &value = *parsed.value;
	const auto event = String(Field(value, "event"));
	const auto messageTopic = String(Field(value, "topic"));
	const auto reference = String(Field(value, "ref"));
	const auto joinValue = Field(value, "join_ref");
	if (joinValue && !std::holds_alternative<std::nullptr_t>(joinValue->value)
		&& !std::holds_alternative<std::string>(joinValue->value)) return Event::Malformed;
	const auto join = String(joinValue);
	const auto payload = Field(value, "payload");
	const auto status = payload ? String(Field(*payload, "status")) : std::string_view();
	if (event == "phx_reply" && messageTopic == topic && !joinReference.empty() && reference == joinReference) {
		if (!join.empty() && join != joinReference) return Event::Ignore;
		return status == "ok" ? (joined ? Event::Ignore : Event::Joined) : Event::ChannelClosed;
	}
	if (event == "phx_reply" && messageTopic == "phoenix" && !heartbeatReference.empty() && reference == heartbeatReference) {
		return status == "ok" ? Event::HeartbeatAck : Event::ChannelClosed;
	}
	if (messageTopic != topic || (!join.empty() && join != joinReference)) return Event::Ignore;
	if (event == "phx_error" || event == "phx_close") return Event::ChannelClosed;
	if (joined && event == "broadcast" && payload) {
		const auto hint = String(Field(*payload, "event"));
		if (hint == "blob_changed" || hint == "account_state_changed" || hint == "account_generation_invalidated") return Event::Changed;
	}
	return Event::Ignore;
}

} // namespace Leemen::Sync::Realtime
