#pragma once

namespace Window {
class SessionController;
} // namespace Window

namespace Leemen {

void ShowPrivateSpaceOnboarding(not_null<Window::SessionController*> controller);
void MaybeShowPrivateSpaceOnboarding(not_null<Window::SessionController*> controller);

} // namespace Leemen
