/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "media/view/media_view_open_common.h"

#include "core/application.h"
#include "data/data_document.h"
#include "data/data_document_media.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "data/data_photo.h"
#include "data/data_web_page.h"
#include "history/history.h"
#include "history/history_item.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/leemen_private_space.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"

#include <QtGui/QGuiApplication>

namespace Media::View {

Leemen::PublicMediaSelection PublicMessageMediaSelection(
		not_null<HistoryItem*> item,
		PhotoData *photo,
		DocumentData *document,
		std::uint64_t request) {
	if (bool(photo) == bool(document)) return {};
	return {
		.session = std::uint64_t(item->history()->session().uniqueId()),
		.peer = item->history()->peer->id.value,
		.message = item->id.bare,
		.media = photo ? photo->id : document->id,
		.kind = photo ? Leemen::PublicMediaKind::Photo
			: Leemen::PublicMediaKind::Document,
		.request = request,
	};
}

bool PublicMessageMediaAllowed(
		not_null<HistoryItem*> item,
		PhotoData *photo,
		DocumentData *document) {
	const auto session = &item->history()->session();
	const auto &space = session->leemen();
	const auto media = item->media();
	if (!session->domain().started()
		|| &session->domain().active() != &session->account()
		|| session->account().maybeSession() != session
		|| QGuiApplication::applicationState() != Qt::ApplicationActive
		|| Core::App().passcodeLocked()
		|| !Leemen::PrivateAccountContentAllowed(session)
		|| space.active() || !space.hidden(item->history()->peer->id)
		|| !space.messageStateReady() || !space.allowsMessage(item->fullId())
		|| item->isHiddenSavedMessage() || item->isService()
		|| !media || media->webpage() || media->invoice() || media->game()
		|| media->poll() || media->storyId() || media->ttlSeconds()
		|| media->ttlSecondsSingleView() || item->isTtlCoveredMedia()
		|| bool(photo) == bool(document)) {
		return false;
	}
	if (photo) {
		return media->photo() == photo && !photo->isNull()
			&& &photo->session() == session;
	}
	const auto documentMedia = document->activeMediaView();
	return media->document() == document && &document->session() == session
		&& !document->isTheme() && !document->inappPlaybackFailed()
		&& (document->isVideoFile() || document->isVideoMessage()
			|| document->isGifv())
		&& (document->canBeStreamed() || document->saveToCache()
			|| (documentMedia && documentMedia->loaded(true)));
}

TimeId ExtractVideoTimestamp(not_null<HistoryItem*> item) {
	const auto media = item->media();
	if (!media) {
		return 0;
	} else if (const auto timestamp = media->videoTimestamp()) {
		return timestamp;
	} else if (const auto webpage = media->webpage()) {
		return webpage->extractVideoTimestamp();
	}
	return 0;
}

TextWithEntities StripQuoteEntities(TextWithEntities text) {
	for (auto i = text.entities.begin(); i != text.entities.end();) {
		if (i->type() == EntityType::Blockquote) {
			i = text.entities.erase(i);
			continue;
		} else if (i->type() == EntityType::Pre) {
			*i = EntityInText(EntityType::Code, i->offset(), i->length());
		}
		++i;
	}
	return text;
}

} // namespace Media::View
