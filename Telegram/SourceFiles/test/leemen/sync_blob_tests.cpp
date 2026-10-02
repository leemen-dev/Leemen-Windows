#include "leemen/sync_blob.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <random>
#include <string>
#include <vector>

namespace {

using namespace Leemen::Sync;

auto Checks = 0;

void Check(bool condition, const char *expression, int line) {
	++Checks;
	if (!condition) {
		std::cerr << "Line " << line << ": " << expression << '\n';
		std::exit(1);
	}
}

#define CHECK(condition) Check(bool(condition), #condition, __LINE__)

JsonValue Json(std::string_view text) {
	auto parsed = ParseJson(text);
	CHECK(parsed.value.has_value());
	return *parsed.value;
}

Register Reg(std::string state, std::int64_t clock = 1, std::string device = "a") {
	return { std::move(state), clock, std::move(device), {} };
}

std::string FilterText(std::string_view fields = {}) {
	return "{\"schema_version\":2,\"lamport\":0,\"hidden_chat_ids\":{},"
		"\"chats_off_mode_visible\":[]" + std::string(fields) + "}";
}

std::string ContentText(std::string_view fields = {}) {
	return "{\"schema_version\":2,\"lamport\":0,\"per_chat\":{},"
		"\"private_search_dialog_ids\":{},\"private_space_settings\":{}"
		+ std::string(fields) + "}";
}

std::string Replace(std::string text, std::string_view from, std::string_view to) {
	const auto offset = text.find(from);
	CHECK(offset != std::string::npos);
	text.replace(offset, from.size(), to);
	return text;
}

void JsonGrammar() {
	for (const auto text : {
		"null", "true", "false", "0", "-0", "-12.30e+4", "1E-3",
		"[]", "{}", "[0,true,null,\"\"]", "{\"a\":[{}],\"b\":0}",
		" \r\n\t{\"x\":false} \t", "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"",
		"\"\\u0000\\u007f\\u0800\\ud83d\\ude00\"" }) {
		const auto read = ParseJson(text);
		CHECK(read.value.has_value());
		CHECK(read.error.empty());
		const auto encoded = EncodeJson(*read.value);
		CHECK(encoded.has_value());
		CHECK(ParseJson(*encoded).value == read.value);
	}
	for (const auto text : {
		"", " ", "null false", "truex", "NULL", "NaN", "Infinity", "-Infinity",
		"+1", "01", "-01", "1.", ".1", "1e", "1e+", "1e--1", "--1", "-",
		"[1,]", "[,1]", "[1 2]", "{\"a\":1,}", "{a:1}", "{\"a\" 1}",
		"{\"a\":}", "[", "{", "\"", "\"\\x\"", "\"\\u12g4\"",
		"\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800\\u0041\"",
		"\"\\uD800x\"", "\"\\uD800\\uD800\"", "\"line\nfeed\"",
		"/*comment*/1", "[1]//comment", "{\"a\":1,\"a\":2}",
		"{\"a\":1,\"\\u0061\":2}", "{\"x\":{\"a\":0,\"a\":0}}" }) {
		const auto read = ParseJson(text);
		CHECK(!read.value);
		CHECK(!read.error.empty());
	}
	for (const auto &bytes : {
		std::string("\x80"), std::string("\xC0\xAF"), std::string("\xE0\x80\xAF"),
		std::string("\xED\xA0\x80"), std::string("\xF0\x80\x80\xAF"),
		std::string("\xF4\x90\x80\x80"), std::string("\xF5\x80\x80\x80"),
		std::string("\xE2\x82"), std::string("\xC2\x41") }) {
		CHECK(!ParseJson("\"" + bytes + "\"").value);
		CHECK(!ParseJson("{\"" + bytes + "\":1}").value);
		CHECK(!EncodeJson(JsonValue{ bytes }));
	}
	const auto utf8 = std::string("Привет 😀 \xEE\x80\x80");
	CHECK(std::get<std::string>(Json("\"" + utf8 + "\"").value) == utf8);
	CHECK(Json("\"\\ud83d\\ude00\"") == Json("\"😀\""));
	CHECK(!ParseJson(std::string("\xEF\xBB\xBF") + "{}").value);
	CHECK(!ParseJson(std::string("\"a\0b\"", 5)).value);
	CHECK(std::get<std::string>(Json("\"a\\u0000b\"").value).size() == 3);
	CHECK(!EncodeJson(JsonValue{ JsonNumber{ "null" } }));
	CHECK(!EncodeJson(JsonValue{ JsonNumber{ "0,\"injected\":true" } }));
	CHECK(!ExactInt64(JsonValue{ JsonNumber{ "" } }));
	CHECK(!ExactInt64(JsonValue{ JsonNumber{ "1e" } }));
}

void JsonBounds() {
	const auto allowed = std::string(64, '[') + "0" + std::string(64, ']');
	CHECK(ParseJson(allowed).value.has_value());
	CHECK(!ParseJson("[" + allowed + "]").value);
	CHECK(!ParseJson("[[0]]", { .maxDepth = 1 }).value);
	CHECK(ParseJson("[0]", { .maxDepth = 1 }).value.has_value());
	CHECK(ParseJson("[0,1]", { .maxNodes = 3 }).value.has_value());
	CHECK(!ParseJson("[0,1]", { .maxNodes = 2 }).value);
	CHECK(ParseJson("null", { .maxBytes = 4 }).value.has_value());
	CHECK(!ParseJson("null", { .maxBytes = 3 }).value);
	CHECK(!ParseJson("null", { .maxNodes = 0 }).value);
	CHECK(!EncodeJson(Json("[[0]]"), { .maxDepth = 1 }));
	CHECK(!EncodeJson(Json("[0,1]"), { .maxNodes = 2 }));
	CHECK(!EncodeJson(Json("null"), { .maxBytes = 3 }));
	const auto maximal = "\"" + std::string(kMaxBlobPlaintextBytes - 2, 'x') + "\"";
	CHECK(ParseJson(maximal).value.has_value());
	CHECK(!ParseJson(maximal + " ").value);
	CHECK(ParseJson(maximal + " ", { .maxBytes = 1024 * 1024 }).value.has_value());
	CHECK(!ParseJson(std::string(1024 * 1024 + 1, ' '),
		{ .maxBytes = std::numeric_limits<std::size_t>::max() }).value);
	auto nested = JsonValue{};
	for (auto i = 0; i != 65; ++i) {
		nested = JsonValue{ JsonValue::Array{ std::move(nested) } };
	}
	CHECK(!EncodeJson(nested));
}

void ExactNumbers() {
	for (const auto &[text, expected] : std::vector<std::pair<std::string, std::int64_t>>{
		{ "0", 0 }, { "-0", 0 }, { "0.0e9999999999999999999999999", 0 },
		{ "2e0", 2 }, { "2.0", 2 }, { "20e-1", 2 }, { "0.002e3", 2 },
		{ "-2.000E+0", -2 }, { "1.2300e2", 123 },
		{ "9007199254740993", 9007199254740993LL },
		{ "9223372036854775807", std::numeric_limits<std::int64_t>::max() },
		{ "-9223372036854775808", std::numeric_limits<std::int64_t>::min() },
		{ "92233720368547758070e-1", std::numeric_limits<std::int64_t>::max() } }) {
		CHECK(ExactInt64(Json(text)) == expected);
	}
	for (const auto text : {
		"0.1", "2.0000000000000001", "1e-10000000", "1e10000000",
		"9223372036854775808", "-9223372036854775809", "1e99999999999999999999",
		"\"2\"", "true", "null", "[]", "{}" }) {
		CHECK(!ExactInt64(Json(text)));
	}
	for (const auto text : {
		"18446744073709551616", "1e1000000000000000000000000",
		"0.123456789012345678901234567890", "-123456789012345678901234567890" }) {
		CHECK(EncodeJson(Json(text)) == text);
	}
}

void DecodeResults() {
	CHECK(ReadFilterBlob(std::nullopt).status == BlobReadStatus::Absent);
	CHECK(ReadContentBlob(std::nullopt).status == BlobReadStatus::Absent);
	for (const auto text : { "", "null", "[]", "{}", "{\"schema_version\":2}" }) {
		CHECK(ReadFilterBlob(text).status == BlobReadStatus::Invalid);
		CHECK(ReadContentBlob(text).status == BlobReadStatus::Invalid);
	}
	for (const auto version : { "3", "0", "-1", "9223372036854775807" }) {
		const auto text = Replace(FilterText(), "\"schema_version\":2",
			"\"schema_version\":" + std::string(version));
		const auto result = ReadFilterBlob(text);
		CHECK(result.status == BlobReadStatus::UnsupportedSchema);
		CHECK(!result.blob);
	}
	for (const auto version : { "\"2\"", "2.0000000000000001", "null", "true", "1e9999" }) {
		CHECK(ReadFilterBlob(Replace(FilterText(), "\"schema_version\":2",
			"\"schema_version\":" + std::string(version))).status == BlobReadStatus::Invalid);
	}
	for (const auto version : { "2.0", "2e0", "20e-1" }) {
		CHECK(ReadFilterBlob(Replace(FilterText(), "\"schema_version\":2",
			"\"schema_version\":" + std::string(version))).status == BlobReadStatus::Decoded);
	}
	CHECK(ReadFilterBlob(FilterText()).blob == FilterBlob());
	CHECK(ReadContentBlob(ContentText()).blob == ContentBlob());
	CHECK(ReadContentBlob(ContentText(",\"ps_pin\":null,\"platform\":null")).blob == ContentBlob());
	for (const auto &text : {
		Replace(FilterText(), "\"hidden_chat_ids\":{}", "\"hidden_chat_ids\":null"),
		Replace(FilterText(), "\"hidden_chat_ids\":{}", "\"hidden_chat_ids\":[]"),
		Replace(FilterText(), "\"chats_off_mode_visible\":[]", "\"chats_off_mode_visible\":null"),
		Replace(FilterText(), "\"lamport\":0", "\"lamport\":-1"),
		Replace(FilterText(), "\"lamport\":0", "\"lamport\":0.5"),
		Replace(FilterText(), "\"lamport\":0", "\"lamport\":9223372036854775808"),
		FilterText(",\"pad\":false") }) {
		CHECK(ReadFilterBlob(text).status == BlobReadStatus::Invalid);
	}
	for (const auto field : {
		"\"per_chat\":null", "\"private_search_dialog_ids\":[]",
		"\"private_space_settings\":false" }) {
		const auto key = std::string(field).substr(0, std::string(field).find(':'));
		CHECK(ReadContentBlob(Replace(ContentText(), key + ":{}", field)).status
			== BlobReadStatus::Invalid);
	}
	CHECK(ReadContentBlob(ContentText(",\"platform\":[]")).status == BlobReadStatus::Invalid);
	CHECK(!EncodeFilterBlob(FilterBlob{ .lamport = -1 }));
	auto invalid = FilterBlob();
	invalid.unknownFields["schema_version"] = Json("3");
	CHECK(!EncodeFilterBlob(invalid));
}

void IdentifiersAndRegisters() {
	for (const auto key : {
		"0", "-0", "+1", "01", "-01", " 1", "1 ", "1e3", "1.0",
		"9223372036854775808", "-9223372036854775808", "6917529027641081857" }) {
		auto blob = FilterBlob();
		blob.hiddenChatIds[key] = Reg("present");
		CHECK(!EncodeFilterBlob(blob));
	}
	for (const auto key : { "1", "-1", "9007199254740993", "-9223372036854775807" }) {
		auto blob = FilterBlob();
		blob.hiddenChatIds[key] = Reg("present");
		const auto encoded = EncodeFilterBlob(blob);
		CHECK(encoded.has_value());
		CHECK(ReadFilterBlob(*encoded).blob == blob);
	}
	for (const auto key : { "0", "-1", "01", "+1", "2147483648", "1.0" }) {
		auto blob = ContentBlob();
		blob.perChat["-1"].messageState[key] = Reg("pending");
		CHECK(!EncodeContentBlob(blob));
	}
	for (const auto &reg : { Reg("present", -1), Reg("present", 0, ""), Reg("", 0) }) {
		auto blob = FilterBlob();
		blob.hiddenChatIds["1"] = reg;
		CHECK(!EncodeFilterBlob(blob));
	}
	auto blob = ContentBlob();
	blob.perChat["-1"].messageState["2147483647"] = Reg("future_state", 99);
	blob.perChat["-1"].selfPinned["1"] = Reg("removed", 99);
	blob.privateSearchDialogIds["9007199254740993"] = Reg("present", 99);
	const auto encoded = EncodeContentBlob(blob);
	CHECK(encoded.has_value());
	CHECK(ReadContentBlob(*encoded).blob == blob);
	CHECK(!MessageVisible(blob.perChat.at("-1").messageState.at("2147483647"), blob.perChat.at("-1")));
	CHECK(ProtectsMembership(Reg("future_state")));
	CHECK(!ProtectsMembership(Reg("removed")));
	for (const auto invalidReg : { "null", "{}", "{\"s\":\"present\",\"c\":1}",
		"{\"s\":\"present\",\"c\":\"1\",\"d\":\"a\"}",
		"{\"s\":1,\"c\":1,\"d\":\"a\"}" }) {
		const auto text = Replace(FilterText(), "\"hidden_chat_ids\":{}",
			"\"hidden_chat_ids\":{\"1\":" + std::string(invalidReg) + "}");
		CHECK(ReadFilterBlob(text).status == BlobReadStatus::Invalid);
	}
}

void RoundTripUnknown() {
	const auto raw = R"({"schema_version":2,"lamport":9007199254740993,
"hidden_chat_ids":{"-9007199254740993":{"s":"present","c":9007199254740993,"d":"device","future":{"x":18446744073709551617}}},
"chats_off_mode_visible":["-9007199254740993"],"pad":"aaa",
"future_root":{"fraction":0.123456789012345678901,"huge":1e999999,"text":"\ud83d\ude00","nil":null}})";
	const auto filter = ReadFilterBlob(raw);
	CHECK(filter.status == BlobReadStatus::Decoded);
	CHECK(filter.blob->lamport == 9007199254740993LL);
	const auto encoded = EncodeFilterBlob(*filter.blob);
	CHECK(encoded.has_value());
	CHECK(encoded->find("18446744073709551617") != std::string::npos);
	CHECK(encoded->find("0.123456789012345678901") != std::string::npos);
	CHECK(encoded->find("1e999999") != std::string::npos);
	CHECK(ReadFilterBlob(*encoded).blob == filter.blob);
	const auto contentRaw = R"({"schema_version":2,"lamport":9,
"per_chat":{"-7":{"cleared_at_c":3,"msg_state":{"1":{"s":"hidden","c":5,"d":"a","future":true}},"self_pinned":{},"chat_extension":[null,1e500]}},
"private_search_dialog_ids":{},"private_space_settings":{"unknown_setting":{"v":1},"pin_timeout_minutes":{"v":0,"c":9,"d":"a","future":false}},
"ps_pin":{"s":"none","c":2,"d":"a","future_pin":[1,2]},
"platform":{"android":{"c":9,"dev":"a","tab_sequence":[{"t":1,"l":2}],"n":9007199254740993},"future_os":[1e900,{}]},"unknown":{"a":true}})";
	const auto content = ReadContentBlob(contentRaw);
	CHECK(content.status == BlobReadStatus::Decoded);
	CHECK(ReadContentBlob(*EncodeContentBlob(*content.blob)).blob == content.blob);
	CHECK(content.blob->platform->at("future_os") == Json("[1e900,{}]"));
	auto local = *content.blob;
	local.settings.allowScreenshots = BoolRegister{ false, 10, "windows", {} };
	local.lamport = 10;
	const auto updated = ReadContentBlob(*EncodeContentBlob(local));
	CHECK(updated.blob->platform == content.blob->platform);
	CHECK(updated.blob->perChat == content.blob->perChat);
	CHECK(updated.blob->unknownFields == content.blob->unknownFields);
}

PinRegister ValidPin(std::string state = "set", std::int64_t clock = 1) {
	return { std::move(state), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"AAAAAAAAAAAAAAAAAAAAAA==", "argon2id", clock, "a", {} };
}

void PinsAndSettings() {
	auto blob = ContentBlob();
	blob.pin = ValidPin();
	blob.settings.allowScreenshots = BoolRegister{ false, 2, "a", {} };
	blob.settings.pinTimeoutMinutes = IntRegister{ 0, 2, "a", {} };
	CHECK(ReadContentBlob(*EncodeContentBlob(blob)).blob == blob);
	for (auto i = 0; i != 8; ++i) {
		auto invalid = blob;
		switch (i) {
		case 0: invalid.pin->kdf = "pbkdf2"; break;
		case 1: invalid.pin->hash.reset(); break;
		case 2: invalid.pin->hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB="; break;
		case 3: invalid.pin->salt = "AAAAAAAAAAAAAAAAAAAAAA"; break;
		case 4: invalid.pin->state = "future"; break;
		case 5: invalid.pin->device.clear(); break;
		case 6: invalid.settings.pinTimeoutMinutes->value = -1; break;
		case 7: invalid.settings.allowScreenshots->clock = -1; break;
		}
		CHECK(!EncodeContentBlob(invalid));
	}
	blob.pin = PinRegister{ "none", {}, {}, {}, 2, "a", {} };
	CHECK(EncodeContentBlob(blob).has_value());
	const auto none = MergeContent(ContentBlob(), blob);
	CHECK(none.pin->state == "none");
	CHECK(MergeContent(blob, ContentBlob()).pin == blob.pin);
}

void RegisterMerges() {
	for (const auto states : {
		std::pair{ "present", "removed" }, std::pair{ "removed", "present" } }) {
		auto left = FilterBlob();
		auto right = FilterBlob();
		left.hiddenChatIds["-1"] = Reg(states.first, 1, "a");
		right.hiddenChatIds["-1"] = Reg(states.second, 2, "a");
		CHECK(MergeFilter(left, right).hiddenChatIds.at("-1").state == states.second);
		right.hiddenChatIds["-1"].clock = 1;
		right.hiddenChatIds["-1"].device = "b";
		CHECK(MergeFilter(left, right).hiddenChatIds.at("-1").state == states.second);
		right.hiddenChatIds["-1"].device = "a";
		CHECK(MergeFilter(left, right).hiddenChatIds.at("-1").state == "present");
		CHECK(MergeFilter(left, right) == MergeFilter(right, left));
	}
	auto left = ContentBlob();
	auto right = ContentBlob();
	left.perChat["-1"].messageState["1"] = Reg("hidden", 5, "a");
	right.perChat["-1"].messageState["1"] = Reg("exposed", 5, "z");
	CHECK(MergeContent(left, right).perChat.at("-1").messageState.at("1").state == "hidden");
	left.perChat["-1"].messageState["1"].state = "pending";
	CHECK(MergeContent(left, right).perChat.at("-1").messageState.at("1").state == "pending");
	right.perChat["-1"].messageState["1"].clock = 6;
	CHECK(MergeContent(left, right).perChat.at("-1").messageState.at("1").state == "exposed");
	left.perChat["-1"].messageState["1"] = Reg("future_private", 6, "a");
	CHECK(MergeContent(left, right).perChat.at("-1").messageState.at("1").state == "future_private");
	left.perChat["-1"].selfPinned["1"] = Reg("present");
	right.perChat["-1"].selfPinned["1"] = Reg("removed");
	CHECK(MergeContent(left, right).perChat.at("-1").selfPinned.at("1").state == "removed");
	left.privateSearchDialogIds["-1"] = Reg("removed");
	right.privateSearchDialogIds["-1"] = Reg("present");
	CHECK(MergeContent(left, right).privateSearchDialogIds.at("-1").state == "present");
	left.settings.pinTimeoutMinutes = IntRegister{ 10, 3, "a", {} };
	right.settings.pinTimeoutMinutes = IntRegister{ 0, 3, "a", {} };
	left.settings.allowScreenshots = BoolRegister{ true, 3, "a", {} };
	right.settings.allowScreenshots = BoolRegister{ false, 3, "a", {} };
	left.pin = ValidPin("none", 3);
	right.pin = ValidPin("set", 3);
	const auto merged = MergeContent(left, right);
	CHECK(merged.settings.pinTimeoutMinutes->value == 0);
	CHECK(!merged.settings.allowScreenshots->value);
	CHECK(merged.pin->state == "set");
	CHECK(merged == MergeContent(right, left));
	right.pin->clock = 4;
	right.pin->state = "none";
	CHECK(MergeContent(left, right).pin->state == "none");
	auto unicodeLeft = FilterBlob();
	auto unicodeRight = FilterBlob();
	unicodeLeft.hiddenChatIds["1"] = Reg("present", 1, "😀");
	unicodeRight.hiddenChatIds["1"] = Reg("removed", 1, "\xEE\x80\x80");
	CHECK(MergeFilter(unicodeLeft, unicodeRight).hiddenChatIds.at("1").state == "removed");
}

void CascadesAndProjection() {
	auto filter = FilterBlob();
	filter.hiddenChatIds["-1"] = Reg("present", 10);
	filter.hiddenChatIds["-2"] = Reg("removed", 10);
	filter.hiddenChatIds["-3"] = Reg("future", 10);
	filter.chatsOffModeVisible = { "999" };
	filter.padding = "aaa";
	auto content = ContentBlob();
	content.perChat["-1"].clearedAtClock = 10;
	content.perChat["-1"].messageState["1"] = Reg("exposed", 9);
	content.perChat["-2"].messageState["1"] = Reg("pending", 20);
	content.perChat["-3"].messageState["1"] = Reg("hidden", 20);
	content.perChat["-4"].messageState["1"] = Reg("exposed", 20);
	RecomputeOffModeVisible(filter, content);
	CHECK(filter.chatsOffModeVisible.empty());
	content.perChat["-1"].messageState["2"] = Reg("pending", 10);
	content.perChat["-3"].messageState["2"] = Reg("exposed", 10);
	RecomputeOffModeVisible(filter, content);
	CHECK(filter.chatsOffModeVisible == std::vector<std::string>({ "-1", "-3" }));
	auto remote = ContentBlob();
	remote.perChat["-1"].clearedAtClock = 11;
	remote.perChat["-1"].selfPinned["9"] = Reg("removed", 9);
	const auto merged = MergeContent(content, remote);
	CHECK(merged.perChat.at("-1").messageState.size() == 2);
	CHECK(merged.perChat.at("-1").selfPinned.at("9").state == "removed");
	RecomputeOffModeVisible(filter, merged);
	CHECK(filter.chatsOffModeVisible == std::vector<std::string>({ "-3" }));
	const auto mergedFilter = MergeFilter(filter, FilterBlob());
	CHECK(mergedFilter.chatsOffModeVisible.empty());
	CHECK(!mergedFilter.padding);
	CHECK(mergedFilter.hiddenChatIds == filter.hiddenChatIds);
	content.perChat["-3"].messageState.clear();
	content.perChat["-3"].messageState["-1"] = Reg("exposed", 11);
	RecomputeOffModeVisible(filter, content);
	CHECK(std::find(filter.chatsOffModeVisible.begin(), filter.chatsOffModeVisible.end(), "-3")
		== filter.chatsOffModeVisible.end());
}

void PlatformMerges() {
	auto left = ContentBlob();
	auto right = ContentBlob();
	left.platform = JsonValue::Object{
		{ "android", Json(R"({"c":2,"dev":"a","setting":"local","unknown":1e400})") },
		{ "ios", Json(R"({"c":1,"dev":"a","keep":true})") },
		{ "ux_onboarding_future", Json(R"({"c":1,"dev":"a","shown":true})") } };
	right.platform = JsonValue::Object{
		{ "android", Json(R"({"c":3,"dev":"a","setting":"remote"})") },
		{ "windows", Json(R"({"c":1,"dev":"b","entry":true})") },
		{ "ux_onboarding_future", Json(R"({"c":99,"dev":"z","shown":false})") } };
	const auto merged = MergeContent(left, right);
	CHECK(merged.platform->size() == 4);
	CHECK(merged.platform->at("ios") == left.platform->at("ios"));
	CHECK(merged.platform->at("android") == right.platform->at("android"));
	CHECK(merged.platform->at("ux_onboarding_future") == left.platform->at("ux_onboarding_future"));
	CHECK(merged == MergeContent(right, left));
	right.platform->at("android") = Json(R"({"c":2,"dev":"z","setting":"remote"})");
	CHECK(MergeContent(left, right).platform->at("android") == right.platform->at("android"));
	right.platform->at("ux_onboarding_future") = Json("null");
	CHECK(MergeContent(left, right).platform->at("ux_onboarding_future")
		== left.platform->at("ux_onboarding_future"));
	left.unknownFields["root"] = Json(R"({"future":1e999})");
	right.unknownFields["other"] = Json("true");
	right.unknownFields["root"] = Json(R"({"future":2e999})");
	left.settings.unknownFields["x"] = Json("1");
	right.settings.unknownFields["y"] = Json("2");
	CHECK(MergeContent(left, right).unknownFields.size() == 2);
	CHECK(MergeContent(left, right).settings.unknownFields.size() == 2);
	CHECK(MergeContent(left, right) == MergeContent(right, left));
}

void MergeLaws() {
	auto filters = std::vector<FilterBlob>();
	auto contents = std::vector<ContentBlob>();
	for (auto i = 0; i != 9; ++i) {
		auto filter = FilterBlob();
		filter.lamport = i;
		filter.hiddenChatIds["-1"] = Reg(i % 2 ? "present" : "removed", i / 3, i % 3 ? "a" : "b");
		filter.hiddenChatIds[std::to_string(i + 1)] = Reg("present", i);
		filter.unknownFields["extension"] = JsonValue{ JsonNumber{ std::to_string(i) } };
		filters.push_back(filter);
		auto content = ContentBlob();
		content.lamport = i;
		content.perChat["-1"].clearedAtClock = i / 4;
		const auto states = std::vector<std::string>{ "exposed", "pending", "hidden", "future" };
		content.perChat["-1"].messageState["1"] = Reg(states[i % 4], i / 3, i % 2 ? "a" : "b");
		content.perChat["-1"].messageState["1"].unknownFields["future"] = Json(std::to_string(i));
		content.perChat["-1"].selfPinned = filter.hiddenChatIds;
		content.perChat["-1"].selfPinned.erase("-1");
		content.privateSearchDialogIds = filter.hiddenChatIds;
		content.settings.pinTimeoutMinutes = IntRegister{ i % 3, i / 3, "a", {} };
		content.settings.allowScreenshots = BoolRegister{ (i % 2) == 1, i / 3, "a", {} };
		content.pin = ValidPin(i % 2 ? "set" : "none", i / 3);
		content.platform = JsonValue::Object{
			{ "android", Json("{\"c\":" + std::to_string(i / 3) + ",\"dev\":\"a\",\"x\":" + std::to_string(i) + "}") },
			{ "ux_onboarding_x", Json("{\"shown\":" + std::string(i % 2 ? "true" : "false") + ",\"c\":" + std::to_string(i) + "}") } };
		contents.push_back(content);
	}
	for (const auto &a : filters) {
		CHECK(MergeFilter(a, a) == a);
		for (const auto &b : filters) {
			CHECK(MergeFilter(a, b) == MergeFilter(b, a));
			for (const auto &c : filters) {
				CHECK(MergeFilter(MergeFilter(a, b), c) == MergeFilter(a, MergeFilter(b, c)));
			}
		}
	}
	for (const auto &a : contents) {
		CHECK(MergeContent(a, a) == a);
		for (const auto &b : contents) {
			CHECK(MergeContent(a, b) == MergeContent(b, a));
			for (const auto &c : contents) {
				CHECK(MergeContent(MergeContent(a, b), c) == MergeContent(a, MergeContent(b, c)));
			}
		}
	}
}

void Lamport() {
	auto filter = FilterBlob();
	auto content = ContentBlob();
	CHECK(NextLamport(filter, content) == 1);
	CHECK(filter.lamport == 1 && content.lamport == 1);
	content.lamport = 9007199254740993LL;
	CHECK(NextLamport(filter, content) == 9007199254740994LL);
	CHECK(filter.lamport == content.lamport);
	filter.lamport = std::numeric_limits<std::int64_t>::max();
	const auto was = content.lamport;
	CHECK(!NextLamport(filter, content));
	CHECK(content.lamport == was);
	filter.lamport = -1;
	CHECK(!NextLamport(filter, content));
	CHECK(filter.lamport == -1 && content.lamport == was);
	filter = FilterBlob();
	content = ContentBlob();
	filter.hiddenChatIds["1"] = Reg("present", 41);
	CHECK(NextLamport(filter, content) == 42);
	content.perChat["1"].clearedAtClock = 50;
	CHECK(NextLamport(filter, content) == 51);
	content.perChat["1"].messageState["1"] = Reg("hidden", 60);
	CHECK(NextLamport(filter, content) == 61);
	content.perChat["1"].selfPinned["1"] = Reg("removed", 70);
	CHECK(NextLamport(filter, content) == 71);
	content.privateSearchDialogIds["1"] = Reg("present", 80);
	CHECK(NextLamport(filter, content) == 81);
	content.settings.pinTimeoutMinutes = IntRegister{ 0, 90, "a", {} };
	CHECK(NextLamport(filter, content) == 91);
	content.settings.allowScreenshots = BoolRegister{ false, 100, "a", {} };
	CHECK(NextLamport(filter, content) == 101);
	content.pin = ValidPin("set", 110);
	CHECK(NextLamport(filter, content) == 111);
	content.platform = JsonValue::Object{ { "future", Json("{\"c\":9007199254740993}") } };
	CHECK(NextLamport(filter, content) == 9007199254740994LL);
	content.perChat["1"].clearedAtClock = std::numeric_limits<std::int64_t>::max();
	const auto filterBefore = filter;
	const auto contentBefore = content;
	CHECK(!NextLamport(filter, content));
	CHECK(filter == filterBefore && content == contentBefore);
}

void ParserNoise() {
	auto random = std::mt19937(0x1ee);
	const auto alphabet = std::string("{}[],:\"\\truefalsn0123456789-.+eE \n\tXYZ");
	for (auto iteration = 0; iteration != 20000; ++iteration) {
		auto text = std::string();
		const auto length = random() % 100;
		for (auto i = std::uint32_t(); i != length; ++i) {
			text.push_back(alphabet[random() % alphabet.size()]);
		}
		const auto parsed = ParseJson(text);
		if (parsed.value) {
			const auto encoded = EncodeJson(*parsed.value);
			CHECK(encoded.has_value());
			CHECK(ParseJson(*encoded).value == parsed.value);
		} else {
			CHECK(!parsed.error.empty());
		}
	}
}

} // namespace

int main() {
	JsonGrammar();
	JsonBounds();
	ExactNumbers();
	DecodeResults();
	IdentifiersAndRegisters();
	RoundTripUnknown();
	PinsAndSettings();
	RegisterMerges();
	CascadesAndProjection();
	PlatformMerges();
	MergeLaws();
	Lamport();
	ParserNoise();
	std::cout << "sync blob: " << Checks << " checks passed\n";
}
