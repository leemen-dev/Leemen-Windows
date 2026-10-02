#include "leemen/sync_blob.h"

#include "leemen/sync_identifiers.h"

#include <algorithm>
#include <charconv>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace Leemen::Sync {
namespace {

using Object = JsonValue::Object;
using Array = JsonValue::Array;

struct Invalid final : std::runtime_error {
	using std::runtime_error::runtime_error;
};

JsonLimits Bounded(JsonLimits limits) {
	limits.maxBytes = std::min(limits.maxBytes, std::size_t(1024 * 1024));
	limits.maxDepth = std::min(limits.maxDepth, std::size_t(64));
	limits.maxNodes = std::min(limits.maxNodes, std::size_t(131072));
	return limits;
}

[[noreturn]] void Fail(const char *reason) {
	throw Invalid(reason);
}

std::uint32_t Codepoint(std::string_view text, std::size_t &position) {
	if (position == text.size()) {
		Fail("invalid UTF-8");
	}
	const auto first = static_cast<unsigned char>(text[position++]);
	if (first < 0x80) {
		return first;
	}
	const auto count = (first >= 0xC2 && first <= 0xDF) ? 1
		: (first >= 0xE0 && first <= 0xEF) ? 2
		: (first >= 0xF0 && first <= 0xF4) ? 3
		: 0;
	if (!count) {
		Fail("invalid UTF-8");
	}
	auto result = std::uint32_t(first & ((1 << (6 - count)) - 1));
	for (auto i = 0; i < count; ++i) {
		if (position == text.size()) {
			Fail("invalid UTF-8");
		}
		const auto next = static_cast<unsigned char>(text[position++]);
		if ((next & 0xC0) != 0x80) {
			Fail("invalid UTF-8");
		}
		result = (result << 6) | (next & 0x3F);
	}
	if (result < (count == 1 ? 0x80U : count == 2 ? 0x800U : 0x10000U)
		|| result > 0x10FFFF
		|| (result >= 0xD800 && result <= 0xDFFF)) {
		Fail("invalid UTF-8");
	}
	return result;
}

void AppendUtf8(std::string &text, std::uint32_t value) {
	if (value < 0x80) {
		text.push_back(char(value));
	} else if (value < 0x800) {
		text.push_back(char(0xC0 | (value >> 6)));
		text.push_back(char(0x80 | (value & 0x3F)));
	} else if (value < 0x10000) {
		text.push_back(char(0xE0 | (value >> 12)));
		text.push_back(char(0x80 | ((value >> 6) & 0x3F)));
		text.push_back(char(0x80 | (value & 0x3F)));
	} else {
		text.push_back(char(0xF0 | (value >> 18)));
		text.push_back(char(0x80 | ((value >> 12) & 0x3F)));
		text.push_back(char(0x80 | ((value >> 6) & 0x3F)));
		text.push_back(char(0x80 | (value & 0x3F)));
	}
}

class Parser final {
public:
	explicit Parser(std::string_view input, JsonLimits limits = {});
	JsonValue parse();

private:
	void whitespace();
	bool consume(char ch);
	char take();
	std::uint32_t hexQuad();
	std::string string();
	JsonValue number();
	JsonValue value(int depth);

	std::string_view _input;
	JsonLimits _limits;
	std::size_t _position = 0;
	std::size_t _nodes = 0;
};

Parser::Parser(std::string_view input, JsonLimits limits)
: _input(input)
, _limits(Bounded(limits)) {
	if (input.size() > _limits.maxBytes) {
		Fail("blob too large");
	}
}

void Parser::whitespace() {
	while (_position < _input.size()) {
		const auto ch = _input[_position];
		if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
			break;
		}
		++_position;
	}
}

bool Parser::consume(char ch) {
	if (_position < _input.size() && _input[_position] == ch) {
		++_position;
		return true;
	}
	return false;
}

char Parser::take() {
	if (_position == _input.size()) {
		Fail("unexpected end of JSON");
	}
	return _input[_position++];
}

std::uint32_t Parser::hexQuad() {
	auto result = std::uint32_t();
	for (auto i = 0; i < 4; ++i) {
		const auto ch = take();
		const auto digit = (ch >= '0' && ch <= '9') ? ch - '0'
			: (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10
			: (ch >= 'A' && ch <= 'F') ? ch - 'A' + 10 : -1;
		if (digit < 0) {
			Fail("invalid unicode escape");
		}
		result = result * 16 + digit;
	}
	return result;
}

std::string Parser::string() {
	if (!consume('"')) {
		Fail("expected string");
	}
	auto result = std::string();
	while (true) {
		const auto ch = take();
		if (ch == '"') {
			break;
		} else if (static_cast<unsigned char>(ch) < 0x20) {
			Fail("unescaped control character");
		} else if (ch != '\\') {
			result.push_back(ch);
			continue;
		}
		switch (take()) {
		case '"': result.push_back('"'); break;
		case '\\': result.push_back('\\'); break;
		case '/': result.push_back('/'); break;
		case 'b': result.push_back('\b'); break;
		case 'f': result.push_back('\f'); break;
		case 'n': result.push_back('\n'); break;
		case 'r': result.push_back('\r'); break;
		case 't': result.push_back('\t'); break;
		case 'u': {
			auto point = hexQuad();
			if (point >= 0xD800 && point <= 0xDBFF) {
				if (take() != '\\' || take() != 'u') {
					Fail("unpaired unicode surrogate");
				}
				const auto low = hexQuad();
				if (low < 0xDC00 || low > 0xDFFF) {
					Fail("unpaired unicode surrogate");
				}
				point = 0x10000 + ((point - 0xD800) << 10) + low - 0xDC00;
			} else if (point >= 0xDC00 && point <= 0xDFFF) {
				Fail("unpaired unicode surrogate");
			}
			AppendUtf8(result, point);
		} break;
		default: Fail("invalid string escape");
		}
	}
	for (auto position = std::size_t(); position < result.size();) {
		Codepoint(result, position);
	}
	return result;
}

JsonValue Parser::number() {
	const auto start = _position;
	consume('-');
	if (!consume('0')) {
		if (_position == _input.size()
			|| _input[_position] < '1' || _input[_position] > '9') {
			Fail("invalid number");
		}
		while (_position < _input.size()
			&& _input[_position] >= '0' && _input[_position] <= '9') {
			++_position;
		}
	}
	const auto digits = [&] {
		const auto from = _position;
		while (_position < _input.size()
			&& _input[_position] >= '0' && _input[_position] <= '9') {
			++_position;
		}
		if (from == _position) {
			Fail("invalid number");
		}
	};
	if (consume('.')) {
		digits();
	}
	if (consume('e') || consume('E')) {
		if (!consume('+')) {
			consume('-');
		}
		digits();
	}
	return JsonValue{ JsonNumber{
		std::string(_input.substr(start, _position - start)) } };
}

JsonValue Parser::value(int depth) {
	if (std::size_t(depth) > _limits.maxDepth || ++_nodes > _limits.maxNodes) {
		Fail("JSON complexity limit");
	}
	whitespace();
	if (_position == _input.size()) {
		Fail("missing JSON value");
	}
	if (_input[_position] == '"') {
		return JsonValue{ string() };
	} else if (consume('{')) {
		auto result = Object();
		whitespace();
		if (!consume('}')) {
			do {
				whitespace();
				auto key = string();
				whitespace();
				if (!consume(':')) {
					Fail("expected object separator");
				}
				auto entry = value(depth + 1);
				if (!result.emplace(std::move(key), std::move(entry)).second) {
					Fail("duplicate JSON key");
				}
				whitespace();
			} while (consume(','));
			if (!consume('}')) {
				Fail("expected object end");
			}
		}
		return JsonValue{ std::move(result) };
	} else if (consume('[')) {
		auto result = Array();
		whitespace();
		if (!consume(']')) {
			do {
				result.push_back(value(depth + 1));
				whitespace();
			} while (consume(','));
			if (!consume(']')) {
				Fail("expected array end");
			}
		}
		return JsonValue{ std::move(result) };
	}
	for (const auto literal : { "null", "true", "false" }) {
		const auto token = std::string_view(literal);
		if (_input.substr(_position, token.size()) == token) {
			_position += token.size();
			return token == "null" ? JsonValue{}
				: JsonValue{ token == "true" };
		}
	}
	return number();
}

JsonValue Parser::parse() {
	auto result = value(0);
	whitespace();
	if (_position != _input.size()) {
		Fail("trailing JSON data");
	}
	return result;
}

std::optional<std::int64_t> ExactInteger(const JsonValue &value) {
	const auto number = std::get_if<JsonNumber>(&value.value);
	if (!number) {
		return std::nullopt;
	}
	const auto &token = number->token;
	auto digits = std::string();
	auto position = std::size_t(token.starts_with('-') ? 1 : 0);
	auto fraction = 0;
	auto fractional = false;
	for (; position < token.size(); ++position) {
		const auto ch = token[position];
		if (ch == 'e' || ch == 'E') {
			break;
		} else if (ch == '.') {
			fractional = true;
		} else {
			digits.push_back(ch);
			fraction += fractional ? 1 : 0;
		}
	}
	const auto first = digits.find_first_not_of('0');
	if (first == std::string::npos) {
		return 0;
	}
	digits.erase(0, first);
	auto exponent = 0;
	if (position < token.size()) {
		++position;
		const auto negative = token[position] == '-';
		if (negative || token[position] == '+') {
			++position;
		}
		for (; position < token.size(); ++position) {
			if (exponent > 1000000) {
				return std::nullopt;
			}
			exponent = exponent * 10 + token[position] - '0';
		}
		if (negative) {
			exponent = -exponent;
		}
	}
	const auto shift = exponent - fraction;
	if (shift < 0) {
		const auto count = std::size_t(-shift);
		if (count >= digits.size()
			|| digits.find_last_not_of('0') >= digits.size() - count) {
			return std::nullopt;
		}
		digits.resize(digits.size() - count);
	} else if (digits.size() + std::size_t(shift) <= 19) {
		digits.append(std::size_t(shift), '0');
	} else {
		return std::nullopt;
	}
	if (token.starts_with('-')) {
		digits.insert(digits.begin(), '-');
	}
	auto result = std::int64_t();
	const auto parsed = std::from_chars(
		digits.data(), digits.data() + digits.size(), result);
	return (parsed.ec == std::errc()
		&& parsed.ptr == digits.data() + digits.size())
		? std::make_optional(result) : std::nullopt;
}

void Quote(std::string &out, const std::string &text) {
	constexpr auto hex = "0123456789abcdef";
	out.push_back('"');
	for (const auto raw : text) {
		const auto ch = static_cast<unsigned char>(raw);
		if (ch == '"' || ch == '\\') {
			out.push_back('\\');
			out.push_back(raw);
		} else if (ch < 0x20) {
			out.append("\\u00");
			out.push_back(hex[ch >> 4]);
			out.push_back(hex[ch & 15]);
		} else {
			out.push_back(raw);
		}
	}
	out.push_back('"');
}

void WriteJson(
		std::string &out,
		const JsonValue &value,
		std::size_t depth,
		std::size_t &nodes,
		const JsonLimits &limits) {
	if (depth > limits.maxDepth
		|| ++nodes > limits.maxNodes
		|| out.size() > limits.maxBytes) {
		Fail("JSON complexity limit");
	}
	std::visit([&](const auto &entry) {
		using Type = std::decay_t<decltype(entry)>;
		if constexpr (std::is_same_v<Type, std::nullptr_t>) {
			out.append("null");
		} else if constexpr (std::is_same_v<Type, bool>) {
			out.append(entry ? "true" : "false");
		} else if constexpr (std::is_same_v<Type, JsonNumber>) {
			if (!std::holds_alternative<JsonNumber>(Parser(entry.token, limits).parse().value)) {
				Fail("invalid number token");
			}
			out.append(entry.token);
		} else if constexpr (std::is_same_v<Type, std::string>) {
			if (entry.size() > limits.maxBytes) {
				Fail("JSON size limit");
			}
			Quote(out, entry);
		} else {
			constexpr auto object = std::is_same_v<Type, Object>;
			out.push_back(object ? '{' : '[');
			auto first = true;
			for (const auto &child : entry) {
				if (!first) {
					out.push_back(',');
				}
				first = false;
				if constexpr (object) {
					Quote(out, child.first);
					out.push_back(':');
					WriteJson(out, child.second, depth + 1, nodes, limits);
				} else {
					WriteJson(out, child, depth + 1, nodes, limits);
				}
			}
			out.push_back(object ? '}' : ']');
		}
	}, value.value);
	if (out.size() > limits.maxBytes) {
		Fail("blob too large");
	}
}

std::string JsonText(const JsonValue &value, JsonLimits limits = {}) {
	auto result = std::string();
	auto nodes = std::size_t();
	WriteJson(result, value, 0, nodes, Bounded(limits));
	return result;
}

const Object &AsObject(const JsonValue &value) {
	const auto result = std::get_if<Object>(&value.value);
	if (!result) {
		Fail("expected object");
	}
	return *result;
}

const std::string &AsString(const JsonValue &value) {
	const auto result = std::get_if<std::string>(&value.value);
	if (!result) {
		Fail("expected string");
	}
	return *result;
}

JsonValue Required(Object &object, const char *key) {
	const auto i = object.find(key);
	if (i == object.end()) {
		Fail("missing required field");
	}
	auto result = std::move(i->second);
	object.erase(i);
	return result;
}

std::optional<JsonValue> Optional(Object &object, const char *key) {
	const auto i = object.find(key);
	if (i == object.end()) {
		return std::nullopt;
	}
	auto result = std::move(i->second);
	object.erase(i);
	return std::holds_alternative<std::nullptr_t>(result.value)
		? std::nullopt : std::make_optional(std::move(result));
}

std::int64_t Nonnegative(const JsonValue &value) {
	const auto result = ExactInteger(value);
	if (!result || *result < 0) {
		Fail("expected nonnegative int64");
	}
	return *result;
}

template <typename Type>
void ReadClock(Type &result, Object &object) {
	result.clock = Nonnegative(Required(object, "c"));
	result.device = AsString(Required(object, "d"));
	if (result.device.empty()) {
		Fail("empty device id");
	}
}

Register ReadRegister(const JsonValue &value) {
	auto object = AsObject(value);
	auto result = Register();
	result.state = AsString(Required(object, "s"));
	if (result.state.empty()) {
		Fail("empty register state");
	}
	ReadClock(result, object);
	result.unknownFields = std::move(object);
	return result;
}

std::map<std::string, Register> ReadRegisters(
		const JsonValue &value,
		bool peers) {
	auto result = std::map<std::string, Register>();
	for (const auto &[key, child] : AsObject(value)) {
		if (peers ? !ParseCanonicalPeerKey(key) : !ParseCloudMessageKey(key)) {
			Fail("invalid identifier");
		}
		result.emplace(key, ReadRegister(child));
	}
	return result;
}

SpaceSettings ReadSettings(const JsonValue &value) {
	auto object = AsObject(value);
	auto result = SpaceSettings();
	if (const auto field = Optional(object, "pin_timeout_minutes")) {
		auto item = AsObject(*field);
		auto entry = IntRegister();
		entry.value = Nonnegative(Required(item, "v"));
		ReadClock(entry, item);
		entry.unknownFields = std::move(item);
		result.pinTimeoutMinutes = std::move(entry);
	}
	if (const auto field = Optional(object, "allow_screenshots")) {
		auto item = AsObject(*field);
		auto entry = BoolRegister();
		const auto data = Required(item, "v");
		const auto boolean = std::get_if<bool>(&data.value);
		if (!boolean) {
			Fail("expected boolean");
		}
		entry.value = *boolean;
		ReadClock(entry, item);
		entry.unknownFields = std::move(item);
		result.allowScreenshots = std::move(entry);
	}
	result.unknownFields = std::move(object);
	return result;
}

bool Base64Size(const std::string &text, std::size_t size) {
	if (text.size() != ((size + 2) / 3) * 4) {
		return false;
	}
	const auto padding = (3 - size % 3) % 3;
	const auto alphabet = std::string_view(
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
	for (auto i = std::size_t(); i < text.size(); ++i) {
		if (i >= text.size() - padding) {
			if (text[i] != '=') {
				return false;
			}
		} else if (alphabet.find(text[i]) == std::string_view::npos) {
			return false;
		}
	}
	const auto last = alphabet.find(text[text.size() - padding - 1]);
	return !padding || !(last & (padding == 1 ? 3 : 15));
}

PinRegister ReadPin(const JsonValue &value) {
	auto object = AsObject(value);
	auto result = PinRegister();
	result.state = AsString(Required(object, "s"));
	ReadClock(result, object);
	for (const auto &[key, destination] : {
		std::pair{ "hash", &result.hash },
		std::pair{ "salt", &result.salt },
		std::pair{ "kdf", &result.kdf } }) {
		if (const auto entry = Optional(object, key)) {
			*destination = AsString(*entry);
		}
	}
	if (result.state != "none"
		&& (result.state != "set"
			|| result.kdf != "argon2id"
			|| !result.hash || !Base64Size(*result.hash, 32)
			|| !result.salt || !Base64Size(*result.salt, 16))) {
		Fail("invalid PIN register");
	}
	result.unknownFields = std::move(object);
	return result;
}

FilterBlob ReadFilter(Object object) {
	auto result = FilterBlob();
	result.lamport = Nonnegative(Required(object, "lamport"));
	result.hiddenChatIds = ReadRegisters(Required(object, "hidden_chat_ids"), true);
	const auto cache = Required(object, "chats_off_mode_visible");
	const auto array = std::get_if<Array>(&cache.value);
	if (!array) {
		Fail("expected array");
	}
	for (const auto &entry : *array) {
		const auto &key = AsString(entry);
		if (!ParseCanonicalPeerKey(key)) {
			Fail("invalid identifier");
		}
		result.chatsOffModeVisible.push_back(key);
	}
	if (const auto padding = Optional(object, "pad")) {
		result.padding = AsString(*padding);
	}
	result.unknownFields = std::move(object);
	return result;
}

ContentBlob ReadContent(Object object) {
	auto result = ContentBlob();
	result.lamport = Nonnegative(Required(object, "lamport"));
	const auto perChat = Required(object, "per_chat");
	for (const auto &[key, value] : AsObject(perChat)) {
		if (!ParseCanonicalPeerKey(key)) {
			Fail("invalid identifier");
		}
		auto fields = AsObject(value);
		auto chat = PerChat();
		chat.clearedAtClock = Nonnegative(Required(fields, "cleared_at_c"));
		chat.messageState = ReadRegisters(Required(fields, "msg_state"), false);
		chat.selfPinned = ReadRegisters(Required(fields, "self_pinned"), false);
		chat.unknownFields = std::move(fields);
		result.perChat.emplace(key, std::move(chat));
	}
	result.privateSearchDialogIds = ReadRegisters(
		Required(object, "private_search_dialog_ids"), true);
	result.settings = ReadSettings(Required(object, "private_space_settings"));
	if (const auto pin = Optional(object, "ps_pin")) {
		result.pin = ReadPin(*pin);
	}
	if (const auto platform = Optional(object, "platform")) {
		result.platform = AsObject(*platform);
	}
	result.unknownFields = std::move(object);
	return result;
}

template <typename Blob, typename Reader>
BlobRead<Blob> Read(std::optional<std::string_view> input, Reader reader) {
	if (!input) {
		return { BlobReadStatus::Absent, std::nullopt, {} };
	}
	try {
		auto object = AsObject(Parser(*input).parse());
		const auto version = ExactInteger(Required(object, "schema_version"));
		if (!version) {
			Fail("invalid schema version");
		} else if (*version != kBlobSchemaVersion) {
			return { BlobReadStatus::UnsupportedSchema, std::nullopt,
				"unsupported schema version" };
		}
		return { BlobReadStatus::Decoded, reader(std::move(object)), {} };
	} catch (const Invalid &error) {
		return { BlobReadStatus::Invalid, std::nullopt, error.what() };
	}
}

JsonValue Number(std::int64_t value) {
	return JsonValue{ JsonNumber{ std::to_string(value) } };
}

void Add(Object &object, const char *key, JsonValue value) {
	if (!object.emplace(key, std::move(value)).second) {
		Fail("unknown field collides with known field");
	}
}

template <typename Type>
Object ClockObject(const Type &value) {
	auto result = value.unknownFields;
	Add(result, "c", Number(value.clock));
	Add(result, "d", JsonValue{ value.device });
	return result;
}

JsonValue ToJson(const Register &value) {
	auto result = ClockObject(value);
	Add(result, "s", JsonValue{ value.state });
	return JsonValue{ std::move(result) };
}

JsonValue ToJson(const IntRegister &value) {
	auto result = ClockObject(value);
	Add(result, "v", Number(value.value));
	return JsonValue{ std::move(result) };
}

JsonValue ToJson(const BoolRegister &value) {
	auto result = ClockObject(value);
	Add(result, "v", JsonValue{ value.value });
	return JsonValue{ std::move(result) };
}

JsonValue ToJson(const PinRegister &value) {
	auto result = ClockObject(value);
	Add(result, "s", JsonValue{ value.state });
	for (const auto &[key, field] : {
		std::pair{ "hash", &value.hash },
		std::pair{ "salt", &value.salt },
		std::pair{ "kdf", &value.kdf } }) {
		if (*field) {
			Add(result, key, JsonValue{ **field });
		} else if (result.contains(key)) {
			Fail("unknown field collides with known field");
		}
	}
	return JsonValue{ std::move(result) };
}

JsonValue ToJson(const PerChat &value);

template <typename Type>
JsonValue MapJson(const std::map<std::string, Type> &values) {
	auto result = Object();
	for (const auto &[key, value] : values) {
		result.emplace(key, ToJson(value));
	}
	return JsonValue{ std::move(result) };
}

JsonValue ToJson(const PerChat &value) {
	auto result = value.unknownFields;
	Add(result, "cleared_at_c", Number(value.clearedAtClock));
	Add(result, "msg_state", MapJson(value.messageState));
	Add(result, "self_pinned", MapJson(value.selfPinned));
	return JsonValue{ std::move(result) };
}

JsonValue ToJson(const SpaceSettings &value) {
	auto result = value.unknownFields;
	if (result.contains("pin_timeout_minutes")
		|| result.contains("allow_screenshots")) {
		Fail("unknown field collides with known field");
	}
	if (value.pinTimeoutMinutes) {
		Add(result, "pin_timeout_minutes", ToJson(*value.pinTimeoutMinutes));
	}
	if (value.allowScreenshots) {
		Add(result, "allow_screenshots", ToJson(*value.allowScreenshots));
	}
	return JsonValue{ std::move(result) };
}

JsonValue ToJson(const FilterBlob &value) {
	auto result = value.unknownFields;
	Add(result, "schema_version", Number(kBlobSchemaVersion));
	Add(result, "lamport", Number(value.lamport));
	Add(result, "hidden_chat_ids", MapJson(value.hiddenChatIds));
	auto cache = Array();
	for (const auto &key : value.chatsOffModeVisible) {
		cache.push_back(JsonValue{ key });
	}
	Add(result, "chats_off_mode_visible", JsonValue{ std::move(cache) });
	if (value.padding) {
		Add(result, "pad", JsonValue{ *value.padding });
	} else if (result.contains("pad")) {
		Fail("unknown field collides with known field");
	}
	return JsonValue{ std::move(result) };
}

JsonValue ToJson(const ContentBlob &value) {
	auto result = value.unknownFields;
	Add(result, "schema_version", Number(kBlobSchemaVersion));
	Add(result, "lamport", Number(value.lamport));
	Add(result, "per_chat", MapJson(value.perChat));
	Add(result, "private_search_dialog_ids", MapJson(value.privateSearchDialogIds));
	Add(result, "private_space_settings", ToJson(value.settings));
	if (result.contains("ps_pin") || result.contains("platform")) {
		Fail("unknown field collides with known field");
	}
	if (value.pin) {
		Add(result, "ps_pin", ToJson(*value.pin));
	}
	if (value.platform) {
		Add(result, "platform", JsonValue{ *value.platform });
	}
	return JsonValue{ std::move(result) };
}

std::u16string DeviceKey(const std::string &value) {
	auto result = std::u16string();
	for (auto position = std::size_t(); position < value.size();) {
		const auto point = Codepoint(value, position);
		if (point < 0x10000) {
			result.push_back(char16_t(point));
		} else {
			result.push_back(char16_t(0xD800 + ((point - 0x10000) >> 10)));
			result.push_back(char16_t(0xDC00 + ((point - 0x10000) & 0x3FF)));
		}
	}
	return result;
}

template <typename Type>
int CompareClock(const Type &left, const Type &right) {
	if (left.clock != right.clock) {
		return left.clock > right.clock ? 1 : -1;
	}
	if (left.device != right.device) {
		return DeviceKey(left.device) > DeviceKey(right.device) ? 1 : -1;
	}
	return 0;
}

template <typename Type>
Type CanonicalMaximum(const Type &left, const Type &right) {
	return JsonText(ToJson(left)) < JsonText(ToJson(right)) ? right : left;
}

UnknownFields MergeUnknown(const UnknownFields &left, const UnknownFields &right) {
	auto result = left;
	for (const auto &[key, value] : right) {
		const auto i = result.find(key);
		if (i == result.end()) {
			result.emplace(key, value);
		} else if (JsonText(i->second) < JsonText(value)) {
			i->second = value;
		}
	}
	return result;
}

enum class RegisterKind {
	ProtectedSet,
	SelfPinned,
	Message,
};

int Rank(const Register &value, RegisterKind kind) {
	if (kind == RegisterKind::Message) {
		return value.state == "exposed" ? 0
			: value.state == "pending" ? 1
			: value.state == "hidden" ? 2 : 3;
	} else if (kind == RegisterKind::SelfPinned) {
		return value.state == "present" ? 0 : 1;
	}
	return value.state == "removed" ? 0 : value.state == "present" ? 1 : 2;
}

Register MergeRegister(const Register &left, const Register &right, RegisterKind kind) {
	if (left.clock != right.clock) {
		return left.clock > right.clock ? left : right;
	}
	const auto leftRank = Rank(left, kind);
	const auto rightRank = Rank(right, kind);
	if (kind == RegisterKind::Message && leftRank != rightRank) {
		return leftRank > rightRank ? left : right;
	}
	if (const auto compare = CompareClock(left, right)) {
		return compare > 0 ? left : right;
	}
	return leftRank != rightRank ? (leftRank > rightRank ? left : right)
		: CanonicalMaximum(left, right);
}

void MergeRegisters(
		std::map<std::string, Register> &into,
		const std::map<std::string, Register> &other,
		RegisterKind kind) {
	for (const auto &[key, value] : other) {
		const auto i = into.find(key);
		if (i == into.end()) {
			into.emplace(key, value);
		} else {
			i->second = MergeRegister(i->second, value, kind);
		}
	}
}

template <typename Type, typename Tie>
std::optional<Type> MergeOptional(
		const std::optional<Type> &left,
		const std::optional<Type> &right,
		Tie tie) {
	if (!left || !right) {
		return left ? left : right;
	}
	if (const auto compare = CompareClock(*left, *right)) {
		return compare > 0 ? left : right;
	}
	if (const auto compare = tie(*left, *right)) {
		return compare > 0 ? left : right;
	}
	return CanonicalMaximum(*left, *right);
}

const JsonValue *Member(const JsonValue &value, const char *key) {
	const auto object = std::get_if<Object>(&value.value);
	if (!object) {
		return nullptr;
	}
	const auto i = object->find(key);
	return i == object->end() ? nullptr : &i->second;
}

bool MarkerShown(const JsonValue &value) {
	const auto member = Member(value, "shown");
	const auto shown = member ? std::get_if<bool>(&member->value) : nullptr;
	return shown && *shown;
}

std::int64_t PlatformClock(const JsonValue &value) {
	const auto member = Member(value, "c");
	return member ? ExactInteger(*member).value_or(0) : 0;
}

std::string PlatformDevice(const JsonValue &value) {
	const auto member = Member(value, "dev");
	const auto text = member ? std::get_if<std::string>(&member->value) : nullptr;
	return text ? *text : std::string();
}

std::optional<Object> MergePlatform(
		const std::optional<Object> &left,
		const std::optional<Object> &right) {
	if (!left || !right) {
		return left ? left : right;
	}
	auto result = *left;
	for (const auto &[key, remote] : *right) {
		const auto i = result.find(key);
		if (i == result.end()) {
			result.emplace(key, remote);
			continue;
		}
		auto &local = i->second;
		if (key.starts_with("ux_onboarding_")
			&& MarkerShown(local) != MarkerShown(remote)) {
			local = MarkerShown(local) ? local : remote;
		} else if (PlatformClock(local) != PlatformClock(remote)) {
			local = PlatformClock(local) > PlatformClock(remote) ? local : remote;
		} else if (PlatformDevice(local) != PlatformDevice(remote)) {
			local = DeviceKey(PlatformDevice(local)) > DeviceKey(PlatformDevice(remote))
				? local : remote;
		} else if (JsonText(local) < JsonText(remote)) {
			local = remote;
		}
	}
	return result;
}

template <typename Blob, typename Reader>
std::optional<std::string> Encode(const Blob &blob, Reader reader) {
	try {
		auto result = JsonText(ToJson(blob));
		if (reader(std::string_view(result)).status == BlobReadStatus::Decoded) {
			return result;
		}
	} catch (const Invalid &) {
	}
	return std::nullopt;
}

} // namespace

JsonRead ParseJson(std::string_view text, JsonLimits limits) {
	try {
		return { Parser(text, limits).parse(), {} };
	} catch (const Invalid &error) {
		return { std::nullopt, error.what() };
	}
}

std::optional<std::string> EncodeJson(const JsonValue &value, JsonLimits limits) {
	try {
		auto result = JsonText(value, limits);
		if (ParseJson(result, limits).value) {
			return result;
		}
	} catch (const Invalid &) {
	}
	return std::nullopt;
}

std::optional<std::int64_t> ExactInt64(const JsonValue &value) {
	const auto number = std::get_if<JsonNumber>(&value.value);
	if (!number) {
		return std::nullopt;
	}
	const auto parsed = ParseJson(number->token);
	return parsed.value ? ExactInteger(*parsed.value) : std::nullopt;
}

BlobRead<FilterBlob> ReadFilterBlob(std::optional<std::string_view> plaintext) {
	return Read<FilterBlob>(plaintext, ReadFilter);
}

BlobRead<ContentBlob> ReadContentBlob(std::optional<std::string_view> plaintext) {
	return Read<ContentBlob>(plaintext, ReadContent);
}

std::optional<std::string> EncodeFilterBlob(const FilterBlob &blob) {
	return Encode(blob, ReadFilterBlob);
}

std::optional<std::string> EncodeContentBlob(const ContentBlob &blob) {
	return Encode(blob, ReadContentBlob);
}

FilterBlob MergeFilter(const FilterBlob &left, const FilterBlob &right) {
	auto result = left;
	result.lamport = std::max(left.lamport, right.lamport);
	MergeRegisters(result.hiddenChatIds, right.hiddenChatIds, RegisterKind::ProtectedSet);
	result.chatsOffModeVisible.clear();
	result.padding.reset();
	result.unknownFields = MergeUnknown(left.unknownFields, right.unknownFields);
	return result;
}

ContentBlob MergeContent(const ContentBlob &left, const ContentBlob &right) {
	auto result = left;
	result.lamport = std::max(left.lamport, right.lamport);
	for (const auto &[key, remote] : right.perChat) {
		const auto i = result.perChat.find(key);
		if (i == result.perChat.end()) {
			result.perChat.emplace(key, remote);
			continue;
		}
		auto &local = i->second;
		local.clearedAtClock = std::max(local.clearedAtClock, remote.clearedAtClock);
		MergeRegisters(local.messageState, remote.messageState, RegisterKind::Message);
		MergeRegisters(local.selfPinned, remote.selfPinned, RegisterKind::SelfPinned);
		local.unknownFields = MergeUnknown(local.unknownFields, remote.unknownFields);
	}
	MergeRegisters(result.privateSearchDialogIds, right.privateSearchDialogIds,
		RegisterKind::ProtectedSet);
	result.settings.pinTimeoutMinutes = MergeOptional(
		left.settings.pinTimeoutMinutes, right.settings.pinTimeoutMinutes,
		[](const auto &a, const auto &b) {
			return a.value == b.value ? 0 : a.value < b.value ? 1 : -1;
		});
	result.settings.allowScreenshots = MergeOptional(
		left.settings.allowScreenshots, right.settings.allowScreenshots,
		[](const auto &a, const auto &b) {
			return a.value == b.value ? 0 : a.value ? -1 : 1;
		});
	result.settings.unknownFields = MergeUnknown(
		left.settings.unknownFields, right.settings.unknownFields);
	result.pin = MergeOptional(left.pin, right.pin, [](const auto &a, const auto &b) {
		return a.state == b.state ? 0 : a.state == "set" ? 1 : -1;
	});
	result.platform = MergePlatform(left.platform, right.platform);
	result.unknownFields = MergeUnknown(left.unknownFields, right.unknownFields);
	return result;
}

bool ProtectsMembership(const Register &value) {
	return value.state != "removed";
}

bool MessageVisible(const Register &value, const PerChat &chat) {
	return value.clock >= chat.clearedAtClock
		&& (value.state == "pending" || value.state == "exposed");
}

void RecomputeOffModeVisible(FilterBlob &filter, const ContentBlob &content) {
	filter.chatsOffModeVisible.clear();
	for (const auto &[key, chat] : content.perChat) {
		const auto membership = filter.hiddenChatIds.find(key);
		if (membership == filter.hiddenChatIds.end()
			|| !ProtectsMembership(membership->second)) {
			continue;
		}
		for (const auto &[id, state] : chat.messageState) {
			if (ParseCloudMessageKey(id) && MessageVisible(state, chat)) {
				filter.chatsOffModeVisible.push_back(key);
				break;
			}
		}
	}
}

std::optional<std::int64_t> NextLamport(FilterBlob &filter, ContentBlob &content) {
	if (filter.lamport < 0 || content.lamport < 0) {
		return std::nullopt;
	}
	auto clock = std::max(filter.lamport, content.lamport);
	const auto observeRegisters = [&](const auto &values) {
		for (const auto &[key, value] : values) {
			clock = std::max(clock, value.clock);
		}
	};
	observeRegisters(filter.hiddenChatIds);
	observeRegisters(content.privateSearchDialogIds);
	for (const auto &[key, chat] : content.perChat) {
		clock = std::max(clock, chat.clearedAtClock);
		observeRegisters(chat.messageState);
		observeRegisters(chat.selfPinned);
	}
	if (content.settings.pinTimeoutMinutes) {
		clock = std::max(clock, content.settings.pinTimeoutMinutes->clock);
	}
	if (content.settings.allowScreenshots) {
		clock = std::max(clock, content.settings.allowScreenshots->clock);
	}
	if (content.pin) {
		clock = std::max(clock, content.pin->clock);
	}
	if (content.platform) {
		for (const auto &[key, section] : *content.platform) {
			clock = std::max(clock, PlatformClock(section));
		}
	}
	if (clock == std::numeric_limits<std::int64_t>::max()) {
		return std::nullopt;
	}
	filter.lamport = content.lamport = clock + 1;
	return clock + 1;
}

} // namespace Leemen::Sync
