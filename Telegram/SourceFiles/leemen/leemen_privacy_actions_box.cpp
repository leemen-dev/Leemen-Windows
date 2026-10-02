#include "leemen/leemen_privacy_actions_box.h"

#include "base/weak_ptr.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_private_space.h"
#include "leemen/sync_service.h"
#include "main/main_session.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"

#include <crl/crl_on_main.h>
#include <QtCore/QPointer>

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

namespace Leemen {
namespace {

void DowngradeBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	struct State {
		rpl::variable<QString> status;
		bool busy = false;
		bool finished = false;
	};
	const auto state = box->lifetime().make_state<State>();
	const auto weak = base::make_weak(&controller->session());
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	box->setTitle(tr::lng_leemen_downgrade());
	box->addRow(object_ptr<Ui::FlatLabel>(
		box, tr::lng_leemen_downgrade_about(), st::boxLabel));
	const auto accepted = box->addRow(object_ptr<Ui::Checkbox>(
		box, tr::lng_leemen_downgrade_confirm(tr::now), false));
	box->addRow(object_ptr<Ui::FlatLabel>(box, state->status.value(), st::boxLabel));
	const auto complete = crl::guard(box, [=](bool success) {
		state->busy = false;
		state->finished = true;
		state->status = success ? tr::lng_leemen_max_done(tr::now)
			: tr::lng_leemen_max_failed(tr::now);
	});
	box->addButton(tr::lng_leemen_downgrade(), [=] {
		if (!weak || state->busy || state->finished || !accepted->checked()
			|| !weak->leemen().active()) {
			return;
		}
		state->busy = true;
		accepted->setEnabled(false);
		state->status = tr::lng_leemen_max_saving(tr::now);
		if (!weak->leemen().syncService().downgradePrivacy(true, complete) && weakBox) {
			complete(false);
		}
	});
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

void ResetBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	struct State {
		rpl::variable<QString> status;
		bool busy = false;
		bool finished = false;
	};
	const auto state = box->lifetime().make_state<State>();
	const auto weak = base::make_weak(&controller->session());
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	box->setTitle(tr::lng_leemen_reset());
	box->addRow(object_ptr<Ui::FlatLabel>(box, tr::lng_leemen_reset_about(), st::boxLabel));
	const auto repeated = box->addRow(object_ptr<Ui::FlatLabel>(
		box, tr::lng_leemen_reset_repeat_about(), st::boxLabel));
	const auto confirmation = box->addRow(object_ptr<Ui::InputField>(
		box, st::defaultInputField, tr::lng_leemen_reset_type()));
	confirmation->setMaxLength(5);
	const auto pending = weak->leemen().syncService().resetState() == SyncService::ResetState::Pending;
	repeated->setVisible(pending);
	if (pending) {
		state->status = tr::lng_leemen_reset_uncertain(tr::now);
	}
	box->addRow(object_ptr<Ui::FlatLabel>(box, state->status.value(), st::boxLabel));
	const auto submit = [=] {
		if (!weak || state->busy || state->finished) {
			return;
		}
		const auto text = confirmation->getLastText();
		if (text != u"RESET"_q) {
			confirmation->showError();
			return;
		}
		confirmation->clear();
		confirmation->setEnabled(false);
		state->busy = true;
		state->status = tr::lng_leemen_max_saving(tr::now);
		const auto complete = crl::guard(box, [=](bool success) {
			state->busy = false;
			state->finished = success;
			confirmation->setEnabled(!success);
			if (!success && weak
				&& weak->leemen().syncService().resetState() == SyncService::ResetState::Pending) {
				repeated->show();
			}
			state->status = success ? tr::lng_leemen_reset_done(tr::now)
				: tr::lng_leemen_reset_uncertain(tr::now);
		});
		if (!weak->leemen().syncService().resetPrivateSpace(text, complete) && weakBox) {
			complete(false);
		}
	};
	confirmation->submits() | rpl::on_next(submit, confirmation->lifetime());
	box->addButton(tr::lng_leemen_reset(), submit);
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	box->setFocusCallback([=] { confirmation->setFocusFast(); });
}

void ActionsBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto weak = base::make_weak(controller.get());
	box->setTitle(tr::lng_leemen_privacy_actions());
	if (controller->session().leemen().syncService().maxMode()) {
		const auto downgrade = box->addRow(object_ptr<Ui::LinkButton>(
			box, tr::lng_leemen_downgrade(tr::now)));
		downgrade->setClickedCallback([=] {
			if (weak && weak->session().leemen().active()) {
				controller->show(Box(DowngradeBox, controller));
			}
		});
	}
	const auto reset = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_reset(tr::now)));
	reset->setClickedCallback([=] {
		if (weak) {
			ShowPrivateSpaceReset(controller);
		}
	});
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

} // namespace

void ShowPrivacyActions(not_null<Window::SessionController*> controller) {
	const auto &space = controller->session().leemen();
	if (space.active() && space.syncEnabled()) {
		controller->show(Box(ActionsBox, controller));
	}
}

void ShowPrivateSpaceReset(not_null<Window::SessionController*> controller) {
	const auto &space = controller->session().leemen();
	if (space.syncEnabled() && controller->session().leemen().syncService().linked()) {
		controller->show(Box(ResetBox, controller));
	}
}

} // namespace Leemen
