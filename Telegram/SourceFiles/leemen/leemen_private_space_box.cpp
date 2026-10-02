#include "leemen/leemen_private_space_box.h"

#include "base/weak_ptr.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_private_space.h"
#include "main/main_session.h"
#include "ui/boxes/confirm_box.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"

#include <crl/crl_on_main.h>

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

namespace Leemen {
namespace {

not_null<Ui::PasswordInput*> AddPinInput(
		not_null<Ui::GenericBox*> box,
		rpl::producer<QString> placeholder) {
	const auto row = box->addRow(object_ptr<Ui::RpWidget>(box));
	row->resize(row->width(), st::defaultInputField.heightMin);
	const auto input = Ui::CreateChild<Ui::PasswordInput>(
		row,
		st::defaultInputField,
		std::move(placeholder));
	input->setMaxLength(12);
	input->setInputMethodHints(Qt::ImhDigitsOnly
		| Qt::ImhHiddenText
		| Qt::ImhNoPredictiveText);
	row->widthValue() | rpl::on_next([=](int width) {
		input->resize(width, input->height());
	}, input->lifetime());
	return input;
}

void PinBox(
		not_null<Ui::GenericBox*> box,
		not_null<Main::Session*> session,
		bool create) {
	struct State {
		rpl::variable<QString> error;
		std::uint64_t request = 0;
		bool busy = false;
		bool closing = false;
	};
	const auto state = box->lifetime().make_state<State>();
	const auto weakSession = base::make_weak(session);
	const auto enrolled = session->leemen().configured();
	box->setTitle(create
		? tr::lng_leemen_pin_create()
		: tr::lng_leemen_unlock());
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		create ? tr::lng_leemen_local_preview() : tr::lng_leemen_pin_prompt(),
		st::boxLabel));
	const auto input = AddPinInput(box, tr::lng_leemen_pin());
	const auto confirm = create
		? AddPinInput(box, tr::lng_leemen_pin_confirm()).get()
		: nullptr;
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		state->error.value(),
		st::boxLabel));
	const auto cancel = [=] {
		state->closing = true;
		if (weakSession) {
			weakSession->leemen().cancelPinOperation(state->request);
		}
		state->request = 0;
	};
	box->boxClosing() | rpl::on_next(cancel, box->lifetime());
	box->lifetime().add(cancel);
	const auto submit = [=] {
		if (!weakSession || state->busy || state->closing) {
			return;
		}
		auto &space = weakSession->leemen();
		if (space.damaged()
			|| (create && enrolled && !space.active())
			|| (create && !enrolled && space.configured())) {
			box->closeBox();
			return;
		}
		auto pin = input->getLastText();
		if (confirm && pin != confirm->getLastText()) {
			state->error = tr::lng_leemen_pin_mismatch(tr::now);
			confirm->showError();
			return;
		}
		state->busy = true;
		state->error = QString();
		input->clear();
		input->setEnabled(false);
		if (confirm) {
			confirm->clear();
			confirm->setEnabled(false);
		}
		auto done = crl::guard(box, [=](bool success) {
			if (state->closing) {
				return;
			}
			state->busy = false;
			state->request = 0;
			if (!weakSession || success) {
				box->closeBox();
				return;
			}
			input->setEnabled(true);
			if (confirm) {
				confirm->setEnabled(true);
			}
			state->error = weakSession->leemen().retryAfterSeconds()
				? tr::lng_leemen_pin_retry(tr::now)
				: create
				? tr::lng_leemen_pin_format(tr::now)
				: tr::lng_leemen_pin_wrong(tr::now);
			input->showError();
		});
		state->request = create
			? space.setPin(pin, std::move(done))
			: space.unlock(pin, std::move(done));
		pin.fill(QChar(0));
	};
	box->addButton(create ? tr::lng_save() : tr::lng_leemen_unlock(), submit);
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
	QObject::connect(input, &Ui::PasswordInput::submitted, box, [=] {
		if (confirm) {
			confirm->setFocus();
		} else {
			submit();
		}
	});
	if (confirm) {
		QObject::connect(confirm, &Ui::PasswordInput::submitted, box, submit);
	}
	box->setFocusCallback([=] { input->setFocus(); });
}

void ManageBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto session = &controller->session();
	const auto weak = base::make_weak(controller.get());
	box->setTitle(tr::lng_leemen_private_space());
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		tr::lng_leemen_active_about(),
		st::boxLabel));
	const auto change = box->addRow(object_ptr<Ui::LinkButton>(
		box,
		tr::lng_leemen_pin_change(tr::now)));
	change->setClickedCallback([=] {
		if (weak && session->leemen().active()) {
			controller->show(Box(PinBox, session, true));
		}
	});
	const auto disable = box->addRow(object_ptr<Ui::LinkButton>(
		box,
		tr::lng_leemen_disable(tr::now)));
	disable->setClickedCallback([=] {
		if (!weak || !session->leemen().active()) {
			return;
		}
		controller->show(Ui::MakeConfirmBox({
			.text = tr::lng_leemen_disable_confirm(),
			.confirmed = [=](Fn<void()> close) {
				close();
				if (weak) {
					session->leemen().disable();
				}
			},
			.confirmText = tr::lng_leemen_disable(),
		}));
	});
	box->addButton(tr::lng_leemen_lock(), [=] {
		session->leemen().lock();
	});
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

} // namespace

void ShowPrivateSpace(not_null<Window::SessionController*> controller) {
	auto &space = controller->session().leemen();
	if (space.damaged()) {
		controller->show(Ui::MakeInformBox(tr::lng_leemen_storage_error()));
	} else if (space.active()) {
		controller->show(Box(ManageBox, controller));
	} else if (space.configured() || PrivateSpace::EnrollmentEnabled()) {
		controller->show(Box(
			PinBox,
			&controller->session(),
			!space.configured()));
	}
}

} // namespace Leemen
