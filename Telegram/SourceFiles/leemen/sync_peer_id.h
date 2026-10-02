#pragma once

#include "data/data_peer_id.h"
#include "leemen/sync_identifiers.h"

namespace Leemen::Sync {

[[nodiscard]] inline std::optional<std::int64_t> CanonicalPeerId(PeerId peer) {
	if (peerIsUser(peer)) {
		return EncodeCanonicalPeerId(peerToUser(peer).bare, CloudPeerKind::User);
	} else if (peerIsChat(peer)) {
		return EncodeCanonicalPeerId(peerToChat(peer).bare, CloudPeerKind::Group);
	} else if (peerIsChannel(peer)) {
		return EncodeCanonicalPeerId(peerToChannel(peer).bare, CloudPeerKind::Channel);
	}
	return std::nullopt;
}

} // namespace Leemen::Sync
