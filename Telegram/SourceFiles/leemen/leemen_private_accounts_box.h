#pragma once

namespace Main { class Account; }
namespace Window { class SessionController; }

namespace Leemen {

void ShowPrivateAccounts(not_null<Window::SessionController*> controller);
void ShowPrivateAccountSwitch(not_null<Main::Account*> target);

} // namespace Leemen
