#include "leemen/local_pin.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

constexpr auto kVectorSalt = std::array<unsigned char, 16>{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

constexpr auto kVectorDigest = std::array<unsigned char, 32>{
	0x18, 0x59, 0x10, 0x67, 0x56, 0x42, 0xb0, 0xff,
	0x4d, 0xc3, 0xfc, 0x90, 0xd7, 0xc0, 0x95, 0x55,
	0xa5, 0xe9, 0xcd, 0xdb, 0x8c, 0x31, 0x57, 0x26,
	0x45, 0x3e, 0xcb, 0x43, 0x5e, 0x0a, 0x71, 0x32,
};

auto Checks = 0;

void Check(bool condition, const char *name) {
	++Checks;
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		std::exit(EXIT_FAILURE);
	}
}

void TestValidation() {
	const auto invalid = {
		std::string(),
		std::string("123"),
		std::string("1234567890123"),
		std::string("12a4"),
		std::string(" 1234"),
		std::string("1234\n"),
		std::string("+1234"),
		std::string("１２３４"),
		std::string("١٢٣٤"),
		std::string("12\0" "34", 5),
	};
	for (const auto &pin : invalid) {
		Check(!Leemen::CreateLocalPin(pin), "reject invalid enrollment");
		Check(!Leemen::VerifyLocalPin(pin, {}), "reject invalid verification");
	}
}

void TestRoundTrip() {
	for (const auto pin : { "0000", "012345678901" }) {
		const auto stored = Leemen::CreateLocalPin(pin);
		Check(stored.has_value(), "enroll boundary length");
		Check(Leemen::VerifyLocalPin(pin, *stored), "verify enrolled PIN");
		Check(!Leemen::VerifyLocalPin("9999", *stored), "reject wrong PIN");
		auto corrupted = *stored;
		corrupted.digest.front() ^= 1;
		Check(!Leemen::VerifyLocalPin(pin, corrupted), "reject corrupt digest");
		corrupted = *stored;
		corrupted.salt.back() ^= 1;
		Check(!Leemen::VerifyLocalPin(pin, corrupted), "reject corrupt salt");
	}
	const auto first = Leemen::CreateLocalPin("246810");
	const auto second = Leemen::CreateLocalPin("246810");
	Check(first && second, "enroll repeated PIN");
	Check(first->salt != second->salt, "random salts differ");
	Check(first->digest != second->digest, "salt changes digest");
	Check(!Leemen::VerifyLocalPin("1234", {}), "reject empty verifier");
}

void TestInteroperability() {
	const auto stored = Leemen::LocalPin{ kVectorSalt, kVectorDigest };
	Check(
		Leemen::VerifyLocalPin("246810", stored),
		"verify independent fixed PBKDF2 vector");
	Check(
		!Leemen::VerifyLocalPin("246811", stored),
		"reject wrong PIN against fixed vector");
}

} // namespace

int main() {
	TestValidation();
	TestRoundTrip();
	TestInteroperability();
	std::cout << "Local PIN checks passed: " << Checks << '\n';
}
