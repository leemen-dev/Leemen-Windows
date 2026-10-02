#include "leemen/leemen_private_space.h"

#include "data/data_session.h"
#include "leemen/security_policy.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/sync_peer_id.h"
#include "leemen/sync_service.h"
#include "main/main_session.h"
#include "main/main_domain.h"

namespace Leemen {

int PrivateSpace::hiddenCount() const {
	auto peers = _syncHidden;
	for (const auto peer : _state.snapshot().hiddenPeers) {
		if (const auto canonical = Sync::CanonicalPeerId(PeerId(peer))) {
			peers.emplace(*canonical);
		}
	}
	return int(peers.size());
}

bool PrivateSpace::requiresLimitResolution() const {
	return _syncEnabled && _sync && Security::EvaluateHiddenLimits(
		_sync->premium().access == Security::PremiumAccess::Active,
		std::size_t(hiddenCount()),
		std::size_t(_session->domain().privateAccounts().hiddenCount(_session))
	).entry == Security::EntryDecision::RenewOrReveal;
}

bool PrivateSpace::managementAllowed() const {
	return (_managementAuthorized || active()) && pinOperationAllowed();
}

bool PrivateSpace::canAddHiddenChat(PeerId peer) const {
	return canHide(peer) && (!_syncEnabled || (_sync && Security::CanAddChats(
		_sync->premium().access == Security::PremiumAccess::Active,
		std::size_t(hiddenCount()),
		hidden(peer) ? 0 : 1)));
}

std::vector<PeerId> PrivateSpace::hiddenPeersForManagement() const {
	if (!managementAllowed()) {
		return {};
	}
	auto peers = std::map<std::int64_t, PeerId>();
	for (const auto peer : _state.snapshot().hiddenPeers) {
		if (const auto canonical = Sync::CanonicalPeerId(PeerId(peer))) {
			peers.emplace(*canonical, PeerId(peer));
		}
	}
	for (const auto canonical : _syncHidden) {
		if (canonical > 0 && std::uint64_t(canonical) <= PeerId::kChatTypeMask) {
			peers.emplace(canonical, PeerId(UserId(canonical)));
		} else if (canonical < 0 && std::uint64_t(-canonical) <= PeerId::kChatTypeMask) {
			const auto chat = PeerId(ChatId(-canonical));
			const auto channel = PeerId(ChannelId(-canonical));
			peers.emplace(canonical,
				_session->data().peerLoaded(chat) ? chat : channel);
		}
	}
	auto result = std::vector<PeerId>();
	result.reserve(peers.size());
	for (const auto &[canonical, peer] : peers) {
		result.push_back(peer);
	}
	return result;
}

} // namespace Leemen
