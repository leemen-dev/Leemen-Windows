#include "leemen/leemen_private_accounts_box.h"

#include "base/weak_ptr.h"
#include "core/application.h"
#include "data/data_user.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/leemen_private_space.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/labels.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include <crl/crl_on_main.h>
#include <QtCore/QPointer>

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

namespace Leemen {
namespace {

not_null<Ui::PasswordInput*> AddInput(not_null<Ui::GenericBox*> box, rpl::producer<QString> placeholder) {
	const auto row = box->addRow(object_ptr<Ui::RpWidget>(box));
	row->resize(row->width(), st::defaultInputField.heightMin);
	const auto input = Ui::CreateChild<Ui::PasswordInput>(row, st::defaultInputField, std::move(placeholder));
	input->setMaxLength(12);
	input->setInputMethodHints(Qt::ImhDigitsOnly | Qt::ImhHiddenText | Qt::ImhNoPredictiveText);
	row->widthValue() | rpl::on_next([=](int width) { input->resize(width, input->height()); }, input->lifetime());
	return input;
}

void SwitchPinBox(
		not_null<Ui::GenericBox*> box,
		not_null<Main::Session*> owner,
		Main::Account *target) {
	struct State {
		rpl::variable<QString> error;
		std::uint64_t request = 0;
		bool busy = false;
		bool closing = false;
	};
	const auto state = box->lifetime().make_state<State>();
	const auto weakOwner = base::make_weak(owner);
	const auto weakTarget = base::make_weak(target);
	const auto accounts = QPointer<PrivateAccounts>(&owner->domain().privateAccounts());
	const auto create = !target;
	box->setTitle(tr::lng_leemen_accounts_switch_pin());
	box->addRow(object_ptr<Ui::FlatLabel>(box, tr::lng_leemen_accounts_switch_pin_about(), st::boxLabel));
	const auto input = AddInput(box, tr::lng_leemen_pin());
	const auto confirm = create ? AddInput(box, tr::lng_leemen_pin_confirm()).get() : nullptr;
	box->addRow(object_ptr<Ui::FlatLabel>(box, state->error.value(), st::boxLabel));
	const auto cancel = [=] {
		state->closing = true;
		if (accounts) accounts->cancelOperation(state->request);
		state->request = 0;
	};
	box->boxClosing() | rpl::on_next(cancel, box->lifetime());
	box->lifetime().add(cancel);
	const auto submit = [=] {
		if (!weakOwner || !accounts || state->closing || state->busy || (!create && !weakTarget)) return;
		auto pin = input->getLastText();
		if (confirm && (pin.isEmpty() || pin != confirm->getLastText())) {
			state->error = tr::lng_leemen_pin_mismatch(tr::now);
			confirm->showError();
			return;
		}
		state->busy = true;
		state->error = QString();
		input->clear();
		input->setEnabled(false);
		if (confirm) { confirm->clear(); confirm->setEnabled(false); }
		auto done = crl::guard(box, [=](bool success) {
			if (state->closing) return;
			state->busy = false;
			state->request = 0;
			if (success || !weakOwner || !accounts) { box->closeBox(); return; }
			input->setEnabled(true);
			if (confirm) confirm->setEnabled(true);
			state->error = accounts->retryAfterSeconds() ? tr::lng_leemen_pin_retry(tr::now)
				: create ? tr::lng_leemen_pin_format(tr::now) : tr::lng_leemen_pin_wrong(tr::now);
			input->showError();
		});
		state->request = create ? accounts->setSwitchPin(weakOwner.get(), pin, std::move(done))
			: accounts->activateWithPin(weakTarget.get(), pin, std::move(done));
		pin.fill(QChar(0));
	};
	box->addButton(create ? tr::lng_save() : tr::lng_leemen_unlock(), submit);
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
	QObject::connect(input, &Ui::MaskedInputField::submitted, box, submit);
	if (confirm) QObject::connect(confirm, &Ui::MaskedInputField::submitted, box, submit);
	box->setFocusCallback([=] { input->setFocus(); });
	owner->domain().activeValue() | rpl::on_next([=](Main::Account *account) {
		if (!weakOwner || account != &weakOwner->account()) box->closeBox();
	}, box->lifetime());
	Core::App().appDeactivatedValue() | rpl::on_next([=](bool away) { if (away) box->closeBox(); }, box->lifetime());
}

void AccountsBox(not_null<Ui::GenericBox*> box, not_null<Window::SessionController*> controller) {
	struct State {
		std::uint64_t request = 0;
		bool closing = false;
	};
	const auto state = box->lifetime().make_state<State>();
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	const auto owner = &controller->session();
	const auto weakOwner = base::make_weak(owner);
	const auto weakController = base::make_weak(controller);
	const auto accounts = QPointer<PrivateAccounts>(&owner->domain().privateAccounts());
	const auto error = box->lifetime().make_state<rpl::variable<QString>>();
	const auto cancel = [=] {
		state->closing = true;
		if (accounts) accounts->cancelOperation(state->request);
		state->request = 0;
	};
	box->boxClosing() | rpl::on_next(cancel, box->lifetime());
	box->lifetime().add(cancel);
	box->setTitle(tr::lng_leemen_accounts_title());
	box->addRow(object_ptr<Ui::FlatLabel>(box, tr::lng_leemen_accounts_about(), st::boxLabel));
	box->addRow(object_ptr<Ui::FlatLabel>(box, error->value(), st::boxLabel));
	for (const auto &[index, entry] : owner->domain().accounts()) {
		const auto target = entry.get();
		if (target == &owner->account() || !target->maybeSession()) continue;
		const auto weakTarget = base::make_weak(target);
		const auto hidden = accounts->hiddenBy(owner, target);
		if (!hidden && accounts->hidden(target)) continue;
		const auto name = target->session().user()->name();
		const auto button = box->addRow(object_ptr<Ui::LinkButton>(box, hidden
			? tr::lng_leemen_accounts_reveal(tr::now, lt_name, name)
			: tr::lng_leemen_accounts_hide(tr::now, lt_name, name)));
		button->setClickedCallback([=] {
			if (!weakOwner || !weakTarget || !accounts) return;
			const auto success = accounts->setHidden(weakOwner.get(), weakTarget.get(), !hidden);
			if (!weakBox || state->closing) return;
			if (!success) {
				*error = tr::lng_leemen_accounts_failed(tr::now);
				return;
			}
			box->closeBox();
			if (weakController) ShowPrivateAccounts(weakController.get());
		});
		if (hidden && owner->leemen().active()) {
			const auto open = box->addRow(object_ptr<Ui::LinkButton>(box, tr::lng_leemen_accounts_open(tr::now, lt_name, name)));
			open->setClickedCallback([=] {
				box->closeBox();
				if (weakTarget) ShowPrivateAccountSwitch(weakTarget.get());
			});
		}
	}
	if (accounts->unavailableHiddenCount(owner)) {
		const auto reveal = box->addRow(object_ptr<Ui::LinkButton>(box, tr::lng_leemen_accounts_reveal_unavailable(tr::now)));
		reveal->setClickedCallback([=] {
			if (!weakOwner || !accounts) return;
			const auto success = accounts->revealUnavailable(weakOwner.get());
			if (!weakBox || state->closing) return;
			if (success) box->closeBox();
			else *error = tr::lng_leemen_accounts_failed(tr::now);
		});
	}
	const auto setPin = box->addRow(object_ptr<Ui::LinkButton>(box, tr::lng_leemen_accounts_switch_pin(tr::now)));
	setPin->setClickedCallback([=] {
		if (weakOwner && weakController) weakController->show(Box(SwitchPinBox, weakOwner.get(), nullptr));
	});
	if (accounts->hasSwitchPin(owner)) {
		const auto clear = box->addRow(object_ptr<Ui::LinkButton>(box, tr::lng_leemen_accounts_switch_pin_clear(tr::now)));
		clear->setClickedCallback([=] {
			if (!weakOwner || !accounts || state->request || state->closing) return;
			state->request = accounts->setSwitchPin(weakOwner.get(), QString(), crl::guard(box, [=](bool success) {
				if (state->closing) return;
				state->request = 0;
				if (success) box->closeBox();
				else *error = tr::lng_leemen_accounts_failed(tr::now);
			}));
		});
	}
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	owner->domain().activeValue() | rpl::on_next([=](Main::Account *account) {
		if (!weakOwner || account != &weakOwner->account()) box->closeBox();
	}, box->lifetime());
	Core::App().appDeactivatedValue() | rpl::on_next([=](bool away) { if (away) box->closeBox(); }, box->lifetime());
	owner->leemen().changes() | rpl::on_next([=] {
		if (!weakOwner || !weakOwner->leemen().managementAllowed()) box->closeBox();
	}, box->lifetime());
}

} // namespace

void ShowPrivateAccounts(not_null<Window::SessionController*> controller) {
	if (!controller->session().leemen().managementAllowed()) return;
	controller->show(Box(AccountsBox, controller));
}

void ShowPrivateAccountSwitch(not_null<Main::Account*> target) {
	auto &domain = target->domain();
	if (!domain.started() || !domain.active().maybeSession() || !target->maybeSession()) return;
	const auto owner = &domain.active().session();
	auto &accounts = domain.privateAccounts();
	if (!owner->leemen().active() || !accounts.hiddenBy(owner, target)) return;
	if (!accounts.hasSwitchPin(owner)) {
		accounts.activateWithPin(target, QString(), [](bool) {});
	} else if (const auto window = Core::App().activePrimaryWindow(); window && &window->account() == &owner->account()) {
		window->show(Box(SwitchPinBox, owner, target.get()));
	}
}

} // namespace Leemen
