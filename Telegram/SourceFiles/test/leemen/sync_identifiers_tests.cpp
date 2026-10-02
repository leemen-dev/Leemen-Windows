#include "leemen/sync_identifiers.h"

#include <array>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

namespace {

using namespace Leemen::Sync;

auto Checks = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

void TestPeerKinds() {
	Check(EncodeCanonicalPeerId(123, CloudPeerKind::User) == 123,
		"user canonical id is positive");
	for (const auto kind : { CloudPeerKind::Group, CloudPeerKind::Channel }) {
		Check(EncodeCanonicalPeerId(123, kind) == -123,
			"group and channel canonical ids are negative");
		Check(DecodeCanonicalPeerId(-123, kind) == 123,
			"negative canonical id decodes with caller peer kind");
		Check(!DecodeCanonicalPeerId(123, kind), "reject peer kind mismatch");
	}
	Check(DecodeCanonicalPeerId(123, CloudPeerKind::User) == 123,
		"user id decodes");
	Check(!DecodeCanonicalPeerId(-123, CloudPeerKind::User),
		"reject negative user id");
	for (const auto kind : {
		CloudPeerKind::User, CloudPeerKind::Group, CloudPeerKind::Channel,
	}) {
		Check(!EncodeCanonicalPeerId(0, kind), "reject zero raw id");
		Check(!EncodeCanonicalPeerId(-1, kind), "reject negative raw id");
		Check(!EncodeCanonicalPeerId(std::numeric_limits<std::int64_t>::min(), kind),
			"reject minimum raw id without overflowing");
		Check(!DecodeCanonicalPeerId(0, kind), "reject zero canonical id");
		Check(!DecodeCanonicalPeerId(std::numeric_limits<std::int64_t>::min(), kind),
			"reject minimum canonical id without overflowing");
	}
	const auto unknown = static_cast<CloudPeerKind>(99);
	Check(!EncodeCanonicalPeerId(1, unknown), "reject unknown encoding peer kind");
	Check(!DecodeCanonicalPeerId(1, unknown), "reject unknown decoding peer kind");
}

void TestCanonicalPeerKeys() {
	const auto valid = std::array<std::int64_t, 7>{
		1, -1, 9007199254740993LL, -9007199254740993LL,
		0x1fffffffffffffffLL, -0x6000000000000001LL,
		-std::numeric_limits<std::int64_t>::max(),
	};
	for (const auto value : valid) {
		const auto key = CanonicalPeerKey(value);
		Check(key && *key == std::to_string(value), "serialize exact decimal peer");
		Check(ParseCanonicalPeerKey(*key) == value, "round-trip exact decimal peer");
	}
	const auto invalid = {
		std::string(), std::string("0"), std::string("-0"), std::string("+1"),
		std::string("01"), std::string("-01"), std::string(" 1"),
		std::string("1 "), std::string("1\n"), std::string("1.0"),
		std::string("1e3"), std::string("0x123"), std::string("１２３"),
		std::string("١٢٣"), std::string("1\0", 2),
		std::string("9223372036854775808"), std::string("-9223372036854775808"),
		std::string("-9223372036854775809"), std::string(100, '9'),
	};
	for (const auto &key : invalid) {
		Check(!ParseCanonicalPeerKey(key), "reject noncanonical peer key");
	}
	Check(!CanonicalPeerKey(0), "reject zero peer serialization");
	Check(!CanonicalPeerKey(std::numeric_limits<std::int64_t>::min()),
		"reject minimum peer serialization");
	for (const auto value : {
		0x2000000000000000LL, 0x2000000000000001LL,
		0x4000000000000000LL, 0x4000000000000001LL,
		0x6000000000000000LL, 0x7fffffffffffffffLL,
	}) {
		Check(!CanonicalPeerKey(value), "reject Android synthetic serialization");
		Check(!ParseCanonicalPeerKey(std::to_string(value)),
			"reject Android synthetic parsing");
		Check(!EncodeCanonicalPeerId(value, CloudPeerKind::User),
			"reject Android synthetic user encoding");
		Check(!DecodeCanonicalPeerId(value, CloudPeerKind::User),
			"reject Android synthetic user decoding");
		Check(EncodeCanonicalPeerId(value, CloudPeerKind::Group) == -value,
			"synthetic namespace applies only to positive canonical ids");
	}
}

void TestCloudMessageKeys() {
	for (const auto value : { 1, 123, std::numeric_limits<std::int32_t>::max() }) {
		const auto key = CloudMessageKey(value);
		Check(key && *key == std::to_string(value), "serialize cloud message");
		Check(ParseCloudMessageKey(*key) == value, "round-trip cloud message");
	}
	for (const auto key : {
		"", "0", "-1", "2147483648", "9223372036854775807", "+1",
		"01", "1 ", " 1", "1.0", "1e3", "１２３", "١٢٣",
	}) {
		Check(!ParseCloudMessageKey(key), "reject invalid cloud message key");
	}
	Check(!ParseCloudMessageKey(std::string("1\0", 2)),
		"reject embedded NUL message key");
	for (const auto value : std::array<std::int64_t, 5>{
		0, -1, 2147483648LL,
		std::numeric_limits<std::int64_t>::min(),
		std::numeric_limits<std::int64_t>::max(),
	}) {
		Check(!CloudMessageKey(value), "reject local or out-of-range message id");
	}
}

} // namespace

int main() {
	TestPeerKinds();
	TestCanonicalPeerKeys();
	TestCloudMessageKeys();
	std::cout << "Sync identifier checks passed: " << Checks << '\n';
}
