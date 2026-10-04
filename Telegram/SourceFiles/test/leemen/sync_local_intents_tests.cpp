#include "leemen/sync_local_intents.h"

#include <cstdlib>
#include <iostream>

namespace {

void Check(bool value, const char *message) {
	if (!value) {
		std::cerr << message << '\n';
		std::exit(EXIT_FAILURE);
	}
}

} // namespace

int main() {
	using namespace Leemen::Sync;
	auto filter = FilterBlob();
	auto content = ContentBlob();
	const auto requested = LocalIntentStamp{ 8, "windows" };
	filter.hiddenChatIds["42"] = Register{ "removed", 3, "android", {} };
	Check(!IsConfirmedLocalRemoval(filter, 42, requested),
		"old remote tombstone accepted as local acknowledgement");
	filter.hiddenChatIds["42"] = Register{ "removed", 8, "android", {} };
	Check(!IsConfirmedLocalRemoval(filter, 42, requested),
		"concurrent device tombstone accepted as local acknowledgement");
	filter.hiddenChatIds["42"] = Register{ "present", 8, "windows", {} };
	Check(!IsConfirmedLocalRemoval(filter, 42, requested),
		"protected membership accepted as removal");
	filter.hiddenChatIds["42"] = Register{ "removed", 8, "windows", {} };
	Check(IsConfirmedLocalRemoval(filter, 42, requested),
		"exact committed removal not recognized");
	Check(!IsConfirmedLocalRemoval(filter, 43, requested),
		"missing peer accepted as removal");
	Check(!IsConfirmedLocalRemoval(filter, 0, requested),
		"invalid peer accepted as removal");
	Check(!IsConfirmedLocalRemoval(filter, 42, {}),
		"legacy unstamped intent accepted");

	content.pin = PinRegister();
	content.pin->state = "none";
	content.pin->clock = 7;
	content.pin->device = "windows";
	Check(!IsConfirmedLocalDisable(filter, content, requested),
		"old disabled PIN accepted as local acknowledgement");
	content.pin->clock = 8;
	content.pin->device = "android";
	Check(!IsConfirmedLocalDisable(filter, content, requested),
		"different device disabled PIN accepted");
	content.pin->device = "windows";
	Check(IsConfirmedLocalDisable(filter, content, requested),
		"exact disable with no protected peers not recognized");
	filter.hiddenChatIds["43"] = Register{ "future-protected", 9, "android", {} };
	Check(!IsConfirmedLocalDisable(filter, content, requested),
		"concurrent unknown protected membership discarded");
	content.pin.reset();
	Check(!IsConfirmedLocalDisable(filter, content, requested),
		"absent PIN accepted as committed disable");
	std::cout << "Sync local intent tests passed.\n";
}
