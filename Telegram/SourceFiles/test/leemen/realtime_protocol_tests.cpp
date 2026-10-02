#include "leemen/realtime_protocol.h"
#include "leemen/sync_blob.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>

namespace {

using namespace Leemen::Sync;
using namespace Leemen::Sync::Realtime;
auto Checks = 0;
constexpr auto kId = "12345678-1234-1234-1234-123456789abc";
constexpr auto kTopic = "realtime:sync:12345678-1234-1234-1234-123456789abc";

void Check(bool value, const char *name) {
	++Checks;
	if (!value) { std::cerr << "FAIL: " << name << '\n'; std::exit(1); }
}

std::span<const unsigned char> Bytes(std::string_view text) {
	return { reinterpret_cast<const unsigned char*>(text.data()), text.size() };
}

std::vector<unsigned char> Server(std::span<const unsigned char> payload, unsigned char opcode = 1, bool final = true) {
	auto frame = std::vector<unsigned char>{ static_cast<unsigned char>((final ? 0x80 : 0) | opcode) };
	if (payload.size() < 126) frame.push_back(static_cast<unsigned char>(payload.size()));
	else {
		frame.push_back(payload.size() <= 65535 ? 126 : 127);
		for (auto i = payload.size() <= 65535 ? 1 : 7; i >= 0; --i) frame.push_back(static_cast<unsigned char>(std::uint64_t(payload.size()) >> (i * 8)));
	}
	frame.insert(frame.end(), payload.begin(), payload.end());
	return frame;
}

std::vector<unsigned char> Server(std::string_view payload, unsigned char opcode = 1, bool final = true) {
	return Server(Bytes(payload), opcode, final);
}

void UpgradeTests() {
	// RFC6455 section 1.3 example, independent of the decoder implementation.
	const auto accept = UpgradeAccept("dGhlIHNhbXBsZSBub25jZQ==");
	Check(accept && *accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "RFC handshake known answer");
	Check(!UpgradeAccept(""), "empty key rejected");
	Check(!UpgradeAccept("dGhlIHNhbXBsZSBub25jZQ=/"), "bad base64 key rejected");
	Check(!UpgradeAccept("dGhlIHNhbXBsZSBub25jZR=="), "noncanonical nonce padding rejected");
	const auto response = std::string("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: ") + *accept + "\r\n\r\n";
	Check(ValidUpgrade(response, *accept), "full RFC upgrade accepted");
	for (auto length = std::size_t(0); length < response.size(); ++length) {
		Check(!ValidUpgrade(std::string_view(response).substr(0, length), *accept), "partial HTTP upgrade not accepted");
	}
	auto wrong = response;
	wrong.replace(9, 3, "1010");
	Check(!ValidUpgrade(wrong, *accept), "status prefix confusion rejected");
	wrong = response;
	wrong.insert(wrong.find("Switching"), "bad\nstatus ");
	Check(!ValidUpgrade(wrong, *accept), "status control injection rejected");
	wrong = response;
	wrong.replace(wrong.find("Upgrade: websocket"), 18, "Upgrade: unrelated");
	Check(!ValidUpgrade(wrong, *accept), "upgrade token required");
	wrong = response;
	wrong.replace(wrong.find("keep-alive, Upgrade"), 19, "keep-alive, Otherxx");
	Check(!ValidUpgrade(wrong, *accept), "connection upgrade token required");
	wrong = response;
	wrong.insert(wrong.size() - 2, "Sec-WebSocket-Accept: " + *accept + "\r\n");
	Check(!ValidUpgrade(wrong, *accept), "duplicate accept rejected");
	for (const auto line : { "Sec-WebSocket-Protocol: unrequested\r\n", "Sec-WebSocket-Extensions: permessage-deflate\r\n", " Upgrade: websocket\r\n", "X: bad\nline\r\n" }) {
		wrong = response;
		wrong.insert(wrong.size() - 2, line);
		Check(!ValidUpgrade(wrong, *accept), "unsolicited extensions or invalid headers rejected");
	}
	Check(!ValidUpgrade(response, "AAAAAAAAAAAAAAAAAAAAAAAAAAA="), "wrong challenge response rejected");
	Check(!ValidUpgrade(std::string(kMaxUpgradeBytes + 1, 'x'), *accept), "header bound enforced");
}

void FrameTests() {
	// RFC6455 section 5.7 masked Hello.
	const auto encoded = ClientFrame(Opcode::Text, Bytes("Hello"), { 0x37, 0xfa, 0x21, 0x3d });
	Check(encoded == std::vector<unsigned char>({ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 }), "RFC masked client frame known answer");
	const auto hello = std::vector<unsigned char>{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
	for (auto split = std::size_t(0); split <= hello.size(); ++split) {
		auto decoder = Decoder();
		auto first = decoder.feed(std::span(hello).first(split));
		auto second = decoder.feed(std::span(hello).subspan(split));
		Check(first && second && first->size() + second->size() == 1, "arbitrary TCP splits preserve one frame");
		const auto &event = first->empty() ? second->front() : first->front();
		Check(event.opcode == Opcode::Text && std::ranges::equal(event.payload, Bytes("Hello")), "split text preserved");
	}
	for (const auto size : { std::size_t(0), std::size_t(125), std::size_t(126), std::size_t(65535), kMaxMessageBytes }) {
		auto decoder = Decoder();
		const auto text = std::vector<unsigned char>(size, 'a');
		const auto frame = Server(text);
		auto events = decoder.feed(frame);
		Check(events && events->size() == 1 && events->front().payload == text, "canonical frame length boundaries");
		Check(ClientFrame(Opcode::Text, text, { 1, 2, 3, 4 }).has_value(), "client length boundaries");
	}
	auto decoder = Decoder();
	auto fragment = Server("Hel", 1, false);
	auto ping = Server("probe", 9);
	auto final = Server("lo", 0);
	fragment.insert(fragment.end(), ping.begin(), ping.end());
	fragment.insert(fragment.end(), final.begin(), final.end());
	auto parsed = decoder.feed(fragment);
	Check(parsed && parsed->size() == 2 && (*parsed)[0].opcode == Opcode::Ping
		&& std::ranges::equal((*parsed)[1].payload, Bytes("Hello")), "control frame interleaves fragmented text");
	decoder.clear();
	const auto unicode = std::vector<unsigned char>{ 0xF0, 0x9F, 0x94, 0x92 };
	Check(decoder.feed(Server(std::span(unicode).first(2), 1, false))->empty(), "UTF8 sequence may cross fragments");
	parsed = decoder.feed(Server(std::span(unicode).subspan(2), 0));
	Check(parsed && parsed->front().payload == unicode, "UTF8 fragment assembly validated after completion");
	for (const auto &bad : std::vector<std::vector<unsigned char>>{
		{0x81, 0x80}, {0xC1, 0}, {0x82, 0}, {0x80, 0}, {0x03, 0}, {0x09, 0},
		{0x89, 126, 0, 126}, {0x81, 126, 0, 1, 'x'}, {0x81, 127, 0,0,0,0,0,0,0,125},
		{0x81, 127, 0x80,0,0,0,0,0,0,0}, {0x81, 127, 0,0,0,0,0,1,0,1},
		{0x88, 1, 0}, {0x88, 2, 3, 237}, {0x88, 2, 3, 238}, {0x88, 2, 7, 208},
		{0x81, 2, 0xC0, 0x80}, {0x81, 3, 0xED, 0xA0, 0x80}, {0x81, 4, 0xF4, 0x90, 0x80, 0x80},
		{0x81, 1, 0x80}, {0x81, 2, 0xE2, 0x82}, {0x88, 3, 3, 232, 0xFF}
	}) {
		decoder.clear();
		Check(!decoder.feed(bad), "malformed websocket or UTF8 rejected");
		Check(!decoder.feed(hello), "protocol error stays latched until reconnect");
	}
	decoder.clear();
	Check(decoder.feed(Server("a", 1, false)).has_value(), "fragment fixture accepted");
	Check(!decoder.feed(Server("b")), "new text while fragmented rejected");
	decoder.clear();
	Check(decoder.feed(Server(std::string(kMaxMessageBytes, 'a'), 1, false)).has_value(), "max-size unfinished message bounded");
	Check(!decoder.feed(Server("b", 0)), "fragment sum bound enforced");
	decoder.clear();
	Check(!decoder.feed(std::vector<unsigned char>(kMaxFeedBytes + 1)), "receive buffer capped");
	decoder.clear();
	auto storm = std::vector<unsigned char>();
	for (auto i = 0; i < 257; ++i) { storm.push_back(0x89); storm.push_back(0); }
	Check(!decoder.feed(storm), "control-frame CPU burst bounded");
	decoder.clear();
	const auto close = decoder.feed(std::array<unsigned char,4>{0x88,2,3,232});
	Check(close && close->front().opcode == Opcode::Close, "valid close delivered");
	Check(!decoder.feed(hello), "no data after close");
	Check(!ClientFrame(Opcode::Ping, std::vector<unsigned char>(126), {}), "client control bound");
	Check(!ClientFrame(Opcode::Close, std::array<unsigned char,1>{0}, {}), "client close validity");
}

void PhoenixTests() {
	Check(Topic(kId) == kTopic, "canonical production topic");
	Check(!Topic("00000000-0000-0000-0000-000000000000") && !Topic("../wrong"), "invalid channel identity rejected");
	const auto join = Join(kId, "public-key", "1");
	Check(join && join->find("\"join_ref\":\"1\"") != std::string::npos
		&& join->find("\"access_token\":\"public-key\"") != std::string::npos
		&& join->find("\"ack\":false") != std::string::npos
		&& join->find("\"private\":false") != std::string::npos, "Android join envelope and anon authorization");
	Check(join && ParseJson(*join).value.has_value(), "join is valid JSON");
	Check(!Join(kId, "key", "0") && !Heartbeat("bad\"reference"), "reference injection rejected");
	Check(Heartbeat("2") == "{\"topic\":\"phoenix\",\"event\":\"heartbeat\",\"payload\":{},\"ref\":\"2\"}", "Android heartbeat envelope");
	const auto event = [&](std::string_view json, bool joined = false) { return Classify(json, kTopic, "1", "2", joined); };
	const auto ack = std::string("{\"topic\":\"") + kTopic + "\",\"event\":\"phx_reply\",\"ref\":\"1\",\"join_ref\":\"1\",\"payload\":{\"status\":\"ok\"}}";
	Check(event(ack) == Event::Joined, "matching channel join accepted");
	Check(event(ack, true) == Event::Ignore, "duplicate join ack cannot amplify hints");
	auto wrong = ack;
	wrong.replace(wrong.find(kTopic), std::string(kTopic).size(), "other");
	Check(event(wrong) == Event::Ignore, "join ack bound to expected channel");
	wrong = ack;
	wrong.replace(wrong.find("\"join_ref\":\"1\""), 14, "\"join_ref\":\"9\"");
	Check(event(wrong) == Event::Ignore, "join epoch checked");
	wrong = ack;
	wrong.replace(wrong.find("\"join_ref\":\"1\""), 14, "\"join_ref\":1");
	Check(event(wrong) == Event::Malformed, "wrong-typed join epoch rejected");
	wrong = ack;
	wrong.replace(wrong.find("\"ok\""), 4, "\"error\"");
	Check(event(wrong) == Event::ChannelClosed, "rejected join reconnects");
	Check(event("{\"topic\":\"phoenix\",\"event\":\"phx_reply\",\"ref\":\"2\",\"payload\":{\"status\":\"ok\"}}", true) == Event::HeartbeatAck, "heartbeat acknowledgement correlated");
	for (const auto hint : { "blob_changed", "account_state_changed", "account_generation_invalidated" }) {
		const auto notification = std::string("{\"topic\":\"") + kTopic + "\",\"event\":\"broadcast\",\"payload\":{\"event\":\"" + hint + "\",\"payload\":{\"version\":-1}}}";
		Check(event(notification, true) == Event::Changed, "broadcast is only a generic reconciliation hint");
		Check(event(notification) == Event::Ignore, "no broadcast before subscription acknowledgement");
	}
	Check(event("[]") == Event::Malformed && event("{broken") == Event::Malformed, "malformed envelope rejected");
	Check(event(std::string(kMaxMessageBytes + 1, ' ')) == Event::Malformed, "JSON byte bound");
	Check(event("{\"event\":\"broadcast\",\"topic\":\"wrong\",\"payload\":{\"event\":\"account_generation_invalidated\"}}", true) == Event::Ignore, "other-account invalidation never authoritative");
}

} // namespace

int main() {
	UpgradeTests();
	FrameTests();
	PhoenixTests();
	std::cout << "Realtime protocol checks passed: " << Checks << '\n';
}
