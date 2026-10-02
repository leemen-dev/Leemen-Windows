#pragma once

#include <QtCore/QString>

namespace Window {
class SessionController;
} // namespace Window

namespace Leemen {

[[nodiscard]] bool PrivateSpaceEntryVisible();
[[nodiscard]] bool HandlePrivateSpaceShortcut();
void ShowPrivateSpaceEntrySettings(not_null<Window::SessionController*> controller);

} // namespace Leemen
