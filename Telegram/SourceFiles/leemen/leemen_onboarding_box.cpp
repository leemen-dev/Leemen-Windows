#include "leemen/leemen_onboarding_box.h"

#include "base/weak_ptr.h"
#include "core/application.h"
#include "core/core_screenshot_protection.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/leemen_private_space.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"

#include <QtCore/QPointer>
#include <QtGui/QGuiApplication>
#include <map>

#include "styles/style_layers.h"

namespace Leemen {
namespace {

bool OnboardingAllowed(not_null<Main::Session*> session) {
	return session->domain().started()
		&& &session->domain().active() == &session->account()
		&& session->account().maybeSession() == session
		&& session->leemen().active()
		&& session->leemen().managementAllowed()
		&& PrivateAccountContentAllowed(session)
		&& QGuiApplication::applicationState() == Qt::ApplicationActive
		&& !Core::App().passcodeLocked();
}

std::map<Main::Session*, QPointer<Ui::GenericBox>> &OpenGuides() {
	static auto result = std::map<Main::Session*, QPointer<Ui::GenericBox>>();
	return result;
}

QString StepTitle(int step) {
	switch (step) {
	case 0: return tr::lng_leemen_tour_step1_title(tr::now);
	case 1: return tr::lng_leemen_tour_step2_title(tr::now);
	case 2: return tr::lng_leemen_tour_step3_title(tr::now);
	case 3: return tr::lng_leemen_tour_step4_title(tr::now);
	}
	Unexpected("Private Space guide step.");
}

QString StepText(int step) {
	switch (step) {
	case 0: return tr::lng_leemen_tour_step1(tr::now);
	case 1: return tr::lng_leemen_tour_step2(tr::now);
	case 2: return tr::lng_leemen_tour_step3(tr::now);
	case 3: return tr::lng_leemen_tour_step4(tr::now);
	}
	Unexpected("Private Space guide step.");
}

void OnboardingBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	struct State {
		rpl::variable<QString> text;
		rpl::variable<QString> advance;
		rpl::variable<QString> status;
		QPointer<Ui::RoundButton> back;
		int step = 0;
		bool finishing = false;
		bool closing = false;
	};
	const auto state = box->lifetime().make_state<State>();
	const auto session = &controller->session();
	const auto weakSession = base::make_weak(session);
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	OpenGuides()[session] = box.get();
	box->lifetime().add([=] {
		const auto i = OpenGuides().find(session);
		if (i != OpenGuides().end() && i->second == weakBox) {
			OpenGuides().erase(i);
		}
	});
	const auto allowed = [=] {
		return !state->closing && weakSession && OnboardingAllowed(session);
	};
	const auto refreshText = [=] {
		state->text = StepTitle(state->step) + u"\n\n"_q + StepText(state->step);
		state->advance = (state->step == 3)
			? tr::lng_leemen_tour_finish(tr::now) : tr::lng_leemen_tour_next(tr::now);
	};
	const auto update = [=] {
		refreshText();
		state->status = QString();
		if (state->back) state->back->setEnabled(state->step > 0);
	};
	box->setTitle(tr::lng_leemen_tour_title());
	box->addRow(object_ptr<Ui::FlatLabel>(box, state->text.value(), st::boxLabel));
	box->addRow(object_ptr<Ui::FlatLabel>(box, tr::lng_leemen_tour_device(), st::boxLabel));
	box->addRow(object_ptr<Ui::FlatLabel>(box, state->status.value(), st::boxLabel));
	const auto lock = box->addRow(object_ptr<Ui::LinkButton>(box, tr::lng_leemen_lock(tr::now)));
	lock->setClickedCallback([=] {
		if (allowed()) session->leemen().lock(true);
	});
	box->addButton(state->advance.value(), [=] {
		if (!allowed() || state->finishing) return;
		if (state->step != 3) {
			++state->step;
			update();
			return;
		}
		state->finishing = true;
		const auto completed = session->leemen().completeOnboarding();
		if (!weakBox || !weakSession) return;
		state->finishing = false;
		if (completed || !allowed()) {
			box->closeBox();
		} else {
			state->status = tr::lng_leemen_tour_save_failed(tr::now);
		}
	});
	state->back = box->addButton(tr::lng_leemen_tour_back(), [=] {
		if (!allowed() || state->finishing || !state->step) return;
		--state->step;
		update();
	});
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	box->boxClosing() | rpl::on_next([=] { state->closing = true; }, box->lifetime());
	Core::App().screenshotProtection().addContentReason(rpl::single(true), box->lifetime());
	const auto closeIfUnavailable = [=] {
		if (!allowed()) box->closeBox();
	};
	session->leemen().changes() | rpl::on_next(closeIfUnavailable, box->lifetime());
	session->domain().activeValue() | rpl::on_next(closeIfUnavailable, box->lifetime());
	session->account().sessionChanges() | rpl::on_next(closeIfUnavailable, box->lifetime());
	Core::App().appDeactivatedValue() | rpl::on_next(closeIfUnavailable, box->lifetime());
	Core::App().passcodeLockValue() | rpl::on_next(closeIfUnavailable, box->lifetime());
	Lang::Updated() | rpl::on_next([=] {
		if (!allowed()) return;
		refreshText();
		if (!state->status.current().isEmpty()) {
			state->status = tr::lng_leemen_tour_save_failed(tr::now);
		}
	}, box->lifetime());
	update();
}

} // namespace

void ShowPrivateSpaceOnboarding(not_null<Window::SessionController*> controller) {
	const auto session = &controller->session();
	if (!OnboardingAllowed(session)) return;
	const auto i = OpenGuides().find(session);
	if (i != OpenGuides().end() && i->second) return;
	controller->show(Box(OnboardingBox, controller), Ui::LayerOption::KeepOther);
}

void MaybeShowPrivateSpaceOnboarding(not_null<Window::SessionController*> controller) {
	const auto &space = controller->session().leemen();
	if (!space.onboardingCompleted() && space.pendingMessages().empty()) {
		ShowPrivateSpaceOnboarding(controller);
	}
}

} // namespace Leemen
