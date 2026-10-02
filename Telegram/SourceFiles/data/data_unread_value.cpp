/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "data/data_unread_value.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "data/data_chat_filters.h"
#include "data/data_folder.h"
#include "data/data_session.h"
#include "main/main_session.h"
#include "leemen/leemen_private_space.h"
#include "window/notifications_manager.h"

namespace Data {
namespace {

rpl::producer<Dialogs::UnreadState> MainListUnreadState(
		not_null<Dialogs::MainList*> list,
		not_null<Main::Session*> session) {
	return rpl::single(rpl::empty) | rpl::then(
		rpl::merge(
			list->unreadStateChanges() | rpl::to_empty,
			session->leemen().changes())
	) | rpl::map([=] {
		return list->visibleUnreadState();
	});
}

} // namespace

[[nodiscard]] Dialogs::UnreadState MainListMapUnreadState(
		not_null<Main::Session*> session,
		const Dialogs::UnreadState &state) {
	const auto folderId = Data::Folder::kId;
	if (const auto folder = session->data().folderLoaded(folderId)) {
		return state - folder->chatsList()->visibleUnreadState();
	}
	return state;
}

rpl::producer<Dialogs::UnreadState> UnreadStateValue(
		not_null<Main::Session*> session,
		FilterId filterId) {
	if (filterId > 0) {
		const auto filters = &session->data().chatsFilters();
		return MainListUnreadState(filters->chatsList(filterId), session);
	}
	return MainListUnreadState(
		session->data().chatsList(), session
	) | rpl::map([=](const Dialogs::UnreadState &state) {
		return MainListMapUnreadState(session, state);
	});
}

rpl::producer<bool> IncludeMutedCounterFoldersValue() {
	using namespace Window::Notifications;
	return rpl::single(rpl::empty_value()) | rpl::then(
		Core::App().notifications().settingsChanged(
		) | rpl::filter(
			rpl::mappers::_1 == ChangeType::IncludeMuted
		) | rpl::to_empty
	) | rpl::map([] {
		return Core::App().settings().includeMutedCounterFolders();
	});
}

} // namespace Data
