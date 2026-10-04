#include "leemen/private_drafts.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

struct Draft {
	std::string text;
	int cursor = 0;
};

void Require(bool condition, const char *message) {
	if (!condition) {
		std::cerr << message << '\n';
		std::exit(EXIT_FAILURE);
	}
}

} // namespace

int main() {
	auto ordinary = Draft{ "ordinary draft", 4 };
	auto drafts = Leemen::PrivateDrafts<int, Draft>();
	auto privateDraft = drafts.get(1, &ordinary);
	Require(privateDraft && privateDraft != &ordinary, "clone required");
	privateDraft->text = "private draft";
	privateDraft->cursor = 10;
	Require(ordinary.text == "ordinary draft" && ordinary.cursor == 4,
		"private edits changed ordinary draft");
	Require(drafts.get(1, &ordinary) == privateDraft,
		"repeated access lost private changes");

	drafts.set(1, nullptr);
	Require(!drafts.get(1, &ordinary), "cleared draft resurrected ordinary");
	drafts.set(2, std::make_unique<Draft>(Draft{ "topic draft", 3 }));
	Require(drafts.get(2, nullptr)->text == "topic draft", "topic missing");
	Require(!drafts.get(1, &ordinary), "topic changed cleared draft");
	drafts.clear();
	Require(!drafts.get(2, nullptr), "private draft survived clearing");
	Require(drafts.get(1, &ordinary)->text == "ordinary draft",
		"ordinary draft not restored for next private session");

	drafts.clear();
	Require(!drafts.get(3, nullptr), "missing draft became nonempty");
	ordinary.text = "server update";
	Require(!drafts.get(3, &ordinary), "late ordinary update replaced private slot");
	drafts.clear();
	Require(drafts.get(3, &ordinary)->text == "server update",
		"new private session missed ordinary update");
	std::cout << "Private drafts tests passed.\n";
}
