#pragma once

#include "data/data_msg_id.h"

namespace Ui {
class PopupMenu;
} // namespace Ui
namespace Window {
class SessionController;
} // namespace Window
namespace Main {
class Session;
} // namespace Main

namespace Leemen {

void ShowPublicMessages(not_null<Window::SessionController*> controller, PeerId peer);
void ShowPendingMessagesDecision(not_null<Main::Session*> session);
void AddPrivateMessageActions(
	not_null<Ui::PopupMenu*> menu,
	not_null<Window::SessionController*> controller,
	FullMsgId id);

} // namespace Leemen
