#pragma once

namespace Window {
class SessionController;
} // namespace Window

namespace Leemen {

void ShowPrivateSpace(not_null<Window::SessionController*> controller);
void ShowPrivateSpaceLimit(not_null<Window::SessionController*> controller);

} // namespace Leemen
