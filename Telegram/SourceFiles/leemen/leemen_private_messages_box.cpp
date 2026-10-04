#include "leemen/leemen_private_messages_box.h"

#include "apiwrap.h"
#include "api/api_common.h"
#include "base/weak_ptr.h"
#include "data/data_changes.h"
#include "data/data_chat_participant_status.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_private_space.h"
#include "leemen/private_message_policy.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "media/view/media_view_open_common.h"
#include "mtproto/mtproto_response.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/popup_menu.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include <crl/crl_on_main.h>
#include <algorithm>

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

namespace Leemen {
namespace {

constexpr auto kPageSize = 25;
constexpr auto kTextLimit = 2048;

bool CanChangePublicPin(not_null<Main::Session*> session, FullMsgId id, bool pin) {
	const auto &space = session->leemen();
	const auto item = session->data().message(id);
	return !space.active() && space.messageStateReady() && space.hidden(id.peer)
		&& IsServerMsgId(id.msg) && space.allowsMessage(id)
		&& item && item->canPin() && !item->isHiddenSavedMessage()
		&& (pin || (space.selfPinned(id) && item->isPinned()));
}

void PublicMessagePinBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller,
		FullMsgId id,
		bool pin) {
	const auto session = &controller->session();
	const auto weakSession = base::make_weak(session);
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	const auto busy = box->lifetime().make_state<bool>(false);
	const auto peer = session->data().peer(id.peer);
	box->setTitle(pin ? tr::lng_pinned_pin() : tr::lng_pinned_unpin());
	box->addRow(object_ptr<Ui::FlatLabel>(box,
		pin ? tr::lng_pinned_pin_sure() : tr::lng_pinned_unpin_sure(), st::boxLabel));
	const auto notify = pin && !peer->isUser()
		? box->addRow(object_ptr<Ui::Checkbox>(box, tr::lng_pinned_notify(tr::now), false))
		: nullptr;
	const auto bothSides = pin && peer->isUser() && !peer->isSelf()
		? box->addRow(object_ptr<Ui::Checkbox>(box,
			tr::lng_leemen_public_pin_both_sides(tr::now), false))
		: nullptr;
	box->addButton(pin ? tr::lng_pinned_pin() : tr::lng_pinned_unpin(), [=] {
		if (*busy || !weakSession || !CanChangePublicPin(session, id, pin)) return;
		*busy = true;
		auto flags = MTPmessages_UpdatePinnedMessage::Flags();
		if (!pin) flags |= MTPmessages_UpdatePinnedMessage::Flag::f_unpin;
		if (!notify || !notify->checked()) flags |= MTPmessages_UpdatePinnedMessage::Flag::f_silent;
		if (bothSides && !bothSides->checked()) flags |= MTPmessages_UpdatePinnedMessage::Flag::f_pm_oneside;
		// This explicit Telegram mutation may finish after its confirmation closes.
		session->api().request(MTPmessages_UpdatePinnedMessage(
			MTP_flags(flags), peer->input(), MTP_int(id.msg)
		)).done([=](const MTPUpdates &updates) {
			const auto weak = weakSession;
			const auto boxGuard = weakBox;
			const auto target = id;
			const auto pinned = pin;
			session->api().applyUpdates(updates);
			if (const auto strong = weak.get()) {
				strong->leemen().recordSelfPin(target, pinned);
			}
			if (boxGuard) boxGuard->closeBox();
		}).fail([=](const MTP::Error &error) {
			if (weakBox && weakSession) {
				*busy = false;
				if (!MTP::IgnoreError(error)) {
					box->setTitle(tr::lng_leemen_public_pin_failed());
				}
			}
		}).send();
	});
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
	session->leemen().changes() | rpl::on_next([=] {
		if (!CanChangePublicPin(session, id, pin)) box->closeBox();
	}, box->lifetime());
}

void ReviewPendingBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto session = &controller->session();
	box->setTitle(tr::lng_leemen_pending_review());
	auto counts = std::map<PeerId, int>();
	for (const auto id : session->leemen().pendingMessages()) ++counts[id.peer];
	for (const auto &[id, count] : counts) {
		const auto peer = session->data().peer(id);
		const auto title = peer->name() + u" ("_q + QString::number(count) + ')';
		const auto button = box->addRow(object_ptr<Ui::SettingsButton>(box, rpl::single(title)));
		button->setClickedCallback([=] {
			if (session->leemen().active()) ShowPublicMessages(controller, id);
		});
	}
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	session->leemen().changes() | rpl::on_next([=] {
		if (!session->leemen().active()) box->closeBox();
	}, box->lifetime());
}

void PendingDecisionBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto session = &controller->session();
	box->setTitle(tr::lng_leemen_pending_decision_title());
	box->addRow(object_ptr<Ui::FlatLabel>(box,
		tr::lng_leemen_pending_decision_about(), st::boxLabel));
	const auto choose = [=](MessageState value) {
		if (!session->leemen().active()) {
			box->closeBox();
			return;
		}
		// A pending local ID may have received its server ID while this box
		// was open. Resolve the current queue at the explicit decision.
		const auto ids = session->leemen().pendingMessages();
		const auto weak = base::make_weak(session);
		box->closeBox();
		if (const auto strong = weak.get()) {
			strong->leemen().resolvePendingMessages(ids, value);
		}
	};
	const auto action = [&](rpl::producer<QString> title, Fn<void()> callback) {
		const auto button = box->addRow(object_ptr<Ui::SettingsButton>(box, std::move(title)));
		button->setClickedCallback(std::move(callback));
	};
	action(tr::lng_leemen_pending_keep_visible(), [=] { choose(MessageState::Exposed); });
	action(tr::lng_leemen_pending_hide(), [=] { choose(MessageState::Hidden); });
	action(tr::lng_leemen_pending_review(), [=] {
		if (!session->leemen().active()) return;
		const auto weak = base::make_weak(controller);
		box->closeBox();
		if (const auto strong = weak.get(); strong && strong->session().leemen().active()) {
			strong->show(Box(ReviewPendingBox, not_null(strong)));
		}
	});
	box->addButton(tr::lng_leemen_pending_later(), [=] { box->closeBox(); });
	session->leemen().changes() | rpl::on_next([=] {
		if (!session->leemen().active()) box->closeBox();
	}, box->lifetime());
}

void PublicMessagesBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller,
		PeerId peerId) {
	const auto session = &controller->session();
	const auto weakViewerSession = base::make_weak(session);
	const auto weakController = base::make_weak(controller);
	const auto peer = session->data().peer(peerId);
	struct State {
		std::set<FullMsgId> requested;
		std::set<FullMsgId> completed;
		QPointer<Ui::RoundButton> send;
		int limit = kPageSize;
		bool queued = false;
		bool closing = false;
		Fn<void()> refresh;
	};
	const auto state = box->lifetime().make_state<State>();
	box->setTitle(rpl::single(peer->name()));
	box->addRow(object_ptr<Ui::FlatLabel>(box,
		tr::lng_leemen_public_messages_about(), st::boxLabel));
	const auto list = box->addRow(object_ptr<Ui::VerticalLayout>(box));
	const auto input = box->addRow(object_ptr<Ui::InputField>(box,
		st::defaultInputField, Ui::InputField::Mode::MultiLine,
		tr::lng_leemen_public_messages_write()));
	input->setMaxLength(kTextLimit);
	box->boxClosing() | rpl::on_next([=] {
		state->closing = true;
		input->clear();
	}, box->lifetime());
	const auto schedule = [=] {
		if (state->closing || state->queued) return;
		state->queued = true;
		crl::on_main(box, [=] {
			state->queued = false;
			if (!state->closing) state->refresh();
		});
	};
	state->refresh = [=] {
		list->clear();
		auto &space = session->leemen();
		if (!space.messageStateReady() || !space.hidden(peerId)) {
			input->clear();
			box->closeBox();
			return;
		}
		input->setVisible(!space.active() && Data::CanSendTexts(peer)
			&& !peer->isForum() && !peer->isMonoforum());
		if (state->send) state->send->setVisible(!space.active() && !input->isHidden());
		auto ids = space.publicMessages(peerId);
		std::sort(ids.begin(), ids.end(), [](FullMsgId a, FullMsgId b) {
			return IsClientMsgId(a.msg) != IsClientMsgId(b.msg)
				? IsClientMsgId(a.msg) : a.msg > b.msg;
		});
		if (ids.empty()) {
			list->add(object_ptr<Ui::FlatLabel>(list,
				tr::lng_leemen_public_messages_empty(), st::boxLabel));
		}
		const auto count = std::min(int(ids.size()), state->limit);
		for (auto index = 0; index != count; ++index) {
			const auto id = ids[index];
			const auto item = session->data().message(id);
			if (!item) {
				list->add(object_ptr<Ui::FlatLabel>(list,
					state->completed.contains(id) || !IsServerMsgId(id.msg)
						? tr::lng_leemen_public_messages_unavailable()
						: tr::lng_leemen_public_messages_loading(), st::boxLabel));
				if (IsServerMsgId(id.msg) && state->requested.emplace(id).second) {
					session->api().requestMessageData(peer, id.msg,
						crl::guard(box, [=] {
							state->completed.emplace(id);
							schedule();
						}));
				}
				continue;
			}
			if (space.messageState(id) == MessageState::Hidden || item->isHiddenSavedMessage()) continue;
			const auto pinService = item->Get<HistoryServicePinned>();
			if (pinService && !VisibleOwnPinService(item->out(),
				!pinService->peerId || pinService->peerId == peerId,
				space.messageState(FullMsgId(peerId, pinService->msgId)))) {
				continue;
			}
			const auto pending = space.messageState(id) == MessageState::Pending;
			auto text = pending ? tr::lng_leemen_message_pending(tr::now) : QString();
			if (item->hasFailed()) text = tr::lng_leemen_public_messages_send_failed(tr::now) + '\n';
			else if (item->isSending()) text = tr::lng_leemen_public_messages_sending(tr::now) + '\n';
			if (space.selfPinned(id) && item->isPinned()) {
				text += tr::lng_leemen_message_self_pinned(tr::now) + '\n';
			}
			text += pinService ? tr::lng_leemen_public_pin_service(tr::now)
				: item->originalText().text;
			if (item->media()) {
				text += '\n' + tr::lng_leemen_public_messages_attachment(tr::now);
			}
			if (text.isEmpty()) text = tr::lng_leemen_public_messages_unavailable(tr::now);
			const auto label = list->add(object_ptr<Ui::FlatLabel>(
				list, rpl::single(text), st::boxLabel));
			label->setSelectable(true);
			const auto media = item->media();
			if (media && Media::View::PublicMessageMediaAllowed(
					item, media->photo(), media->document())) {
				const auto open = list->add(object_ptr<Ui::SettingsButton>(
					list, tr::lng_leemen_public_messages_open_attachment()));
				open->setClickedCallback([=] {
					if (state->closing || !weakViewerSession || !weakController
						|| &weakController->session() != weakViewerSession.get()) return;
					const auto current = weakViewerSession->data().message(id);
					const auto currentMedia = current ? current->media() : nullptr;
					if (!currentMedia || !Media::View::PublicMessageMediaAllowed(
							current, currentMedia->photo(), currentMedia->document())) return;
					auto request = currentMedia->photo()
						? Media::View::OpenRequest(weakController.get(),
							currentMedia->photo(), current, MsgId(), PeerId())
						: Media::View::OpenRequest(weakController.get(),
							currentMedia->document(), current, MsgId(), PeerId());
					request.setPublicMessage();
					weakController->window().openInMediaView(std::move(request));
				});
			}
			if (!space.active()) {
				const auto pin = !space.selfPinned(id) || !item->isPinned();
				if (CanChangePublicPin(session, id, pin)) {
					const auto button = list->add(object_ptr<Ui::SettingsButton>(
						list, pin ? tr::lng_pinned_pin() : tr::lng_pinned_unpin()));
					button->setClickedCallback([=] {
						if (CanChangePublicPin(session, id, pin)) {
							controller->show(Box(PublicMessagePinBox, controller, id, pin),
								Ui::LayerOption::KeepOther);
						}
					});
				}
			}
			if (space.active()) {
				const auto addAction = [&](rpl::producer<QString> title, MessageState value) {
					const auto button = list->add(object_ptr<Ui::SettingsButton>(
						list, std::move(title)));
					button->setClickedCallback([=] {
						session->leemen().setMessageState(id, value);
					});
				};
				if (pending) addAction(tr::lng_leemen_message_expose(), MessageState::Exposed);
				addAction(tr::lng_leemen_message_hide(), MessageState::Hidden);
			}
		}
		if (count < int(ids.size())) {
			const auto more = list->add(object_ptr<Ui::SettingsButton>(
				list, tr::lng_leemen_public_messages_more()));
			more->setClickedCallback([=] {
				state->limit += kPageSize;
				schedule();
			});
		}
	};
	state->send = box->addButton(tr::lng_send_button(), [=] {
		auto &space = session->leemen();
		if (state->closing || space.active() || !space.messageStateReady()
			|| !space.hidden(peerId) || !Data::CanSendTexts(peer)
			|| peer->isForum() || peer->isMonoforum()) return;
		const auto text = input->getTextWithTags().text.trimmed();
		if (text.isEmpty()) return;
		const auto weakBox = QPointer<Ui::GenericBox>(box.get());
		const auto weakSession = base::make_weak(session);
		const auto history = session->data().history(peer);
		const auto id = session->data().nextLocalMessageId();
		if (!space.markOffModeMessage(FullMsgId(peerId, id))) return;
		if (!weakBox || !weakSession || state->closing
			|| space.active() || !space.messageStateReady()
			|| !space.hidden(peerId) || !Data::CanSendTexts(peer)) return;
		auto action = Api::SendAction(history);
		action.clearDraft = false;
		auto message = Api::MessageToSend(action);
		message.textWithTags = { text, {} };
		input->clear();
		session->api().sendMessage(std::move(message), id);
		if (weakBox) schedule();
	});
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	session->leemen().changes() | rpl::on_next([=] {
		list->clear();
		if (!session->leemen().messageStateReady()) {
			input->clear();
			box->closeBox();
		} else {
			schedule();
		}
	}, box->lifetime());
	session->data().itemDataChanges() | rpl::on_next([=](not_null<HistoryItem*> item) {
		if (item->history()->peer->id == peerId) schedule();
	}, box->lifetime());
	session->domain().activeValue() | rpl::on_next([=](Main::Account *account) {
		if (account != &session->account()) box->closeBox();
	}, box->lifetime());
	session->account().sessionChanges() | rpl::on_next([=](Main::Session *current) {
		if (current != session) box->closeBox();
	}, box->lifetime());
	session->data().itemRemoved() | rpl::on_next([=](not_null<const HistoryItem*> item) {
		if (item->history()->peer->id == peerId) {
			list->clear();
			schedule();
		}
	}, box->lifetime());
	session->changes().messageUpdates(Data::MessageUpdate::Flag::Edited
		| Data::MessageUpdate::Flag::NewMaybeAdded
		| Data::MessageUpdate::Flag::NewAdded
	) | rpl::on_next([=](const Data::MessageUpdate &update) {
		if (update.item->history()->peer->id == peerId) schedule();
	}, box->lifetime());
	state->refresh();
}

} // namespace

void ShowPublicMessages(not_null<Window::SessionController*> controller, PeerId peer) {
	const auto session = &controller->session();
	const auto &space = session->leemen();
	if (session->domain().started()
		&& &session->domain().active() == &session->account()
		&& session->account().maybeSession() == session
		&& space.messageStateReady() && space.hidden(peer)) {
		controller->show(Box(PublicMessagesBox, controller, peer));
	}
}

void ShowPendingMessagesDecision(not_null<Main::Session*> session) {
	if (!session->leemen().active() || session->windows().empty()
		|| !session->domain().started()
		|| &session->domain().active() != &session->account()
		|| session->account().maybeSession() != session) {
		return;
	}
	if (session->leemen().pendingMessages().empty()) return;
	if (const auto controller = session->tryResolveWindow()) {
		controller->show(Box(PendingDecisionBox, not_null(controller)));
	}
}

void AddPrivateMessageActions(
		not_null<Ui::PopupMenu*> menu,
		not_null<Window::SessionController*> controller,
		FullMsgId id) {
	const auto session = &controller->session();
	const auto &space = session->leemen();
	if (!space.active() || !space.hidden(id.peer) || !IsServerMsgId(id.msg)) return;
	const auto exposed = space.messageState(id) == MessageState::Exposed;
	menu->addAction(exposed ? tr::lng_leemen_message_hide(tr::now)
		: tr::lng_leemen_message_expose(tr::now), crl::guard(controller, [=] {
		session->leemen().setMessageState(id,
			exposed ? MessageState::Hidden : MessageState::Exposed);
	}));
	menu->addAction(tr::lng_leemen_public_messages_open(tr::now), crl::guard(controller, [=] {
		ShowPublicMessages(controller, id.peer);
	}));
}

} // namespace Leemen
