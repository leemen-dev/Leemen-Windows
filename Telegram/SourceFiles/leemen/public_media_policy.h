#pragma once

#include <cstdint>

namespace Leemen {

enum class PublicMediaKind : unsigned char {
	None,
	Photo,
	Document,
};

struct PublicMediaSelection {
	std::uint64_t session = 0;
	std::uint64_t peer = 0;
	std::int64_t message = 0;
	std::uint64_t media = 0;
	PublicMediaKind kind = PublicMediaKind::None;
	std::uint64_t request = 0;

	friend bool operator==(
		const PublicMediaSelection&,
		const PublicMediaSelection&) = default;
};

[[nodiscard]] inline bool AllowsPublicMedia(
		const PublicMediaSelection &selection,
		const PublicMediaSelection &target,
		bool authorized) {
	return authorized && selection.session && selection.peer
		&& selection.message && selection.media && selection.request
		&& (selection.kind == PublicMediaKind::Photo
			|| selection.kind == PublicMediaKind::Document)
		&& selection == target;
}

} // namespace Leemen
