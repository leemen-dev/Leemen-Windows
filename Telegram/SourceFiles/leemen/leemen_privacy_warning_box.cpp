#include "leemen/leemen_privacy_warning_box.h"

#include "api/api_authorizations.h"
#include "api/api_cloud_password.h"
#include "apiwrap.h"
#include "base/weak_ptr.h"
#include "config.h"
#include "core/application.h"
#include "core/core_cloud_password.h"
#include "core/core_screenshot_protection.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/leemen_private_space.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "settings/sections/settings_active_sessions.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"

#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtGui/QGuiApplication>
#include <algorithm>
#include <rpl/skip.h>

#include "styles/style_layers.h"

namespace Leemen {
namespace {

bool WarningsAllowed(not_null<Main::Session*> session) {
	return session->domain().started()
		&& &session->domain().active() == &session->account()
		&& session->account().maybeSession() == session
		&& session->leemen().active()
		&& PrivateAccountContentAllowed(session)
		&& QGuiApplication::applicationState() == Qt::ApplicationActive
		&& !Core::App().passcodeLocked();
}

void WarningsBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	struct State {
		rpl::variable<QString> password;
		rpl::variable<QString> sessions;
		crl::time sessionsBaseline = 0;
		std::uint64_t request = 0;
		bool passwordPending = false;
		bool sessionsPending = false;
		bool closing = false;
	};
	const auto state = box->lifetime().make_state<State>();
	const auto session = &controller->session();
	const auto weakSession = base::make_weak(session);
	const auto weakController = base::make_weak(controller);
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	const auto allowed = [=] {
		return !state->closing && weakSession && WarningsAllowed(weakSession.get());
	};
	box->setTitle(tr::lng_leemen_privacy_check());
	box->addRow(object_ptr<Ui::FlatLabel>(box,
		tr::lng_leemen_privacy_check_about(), st::boxLabel));
	box->addRow(object_ptr<Ui::FlatLabel>(box, state->password.value(), st::boxLabel));
	const auto password = box->addRow(object_ptr<Ui::LinkButton>(box,
		tr::lng_leemen_privacy_check_password(tr::now)));
	password->setClickedCallback([=] {
		if (!allowed() || !weakController) return;
		box->closeBox();
		if (weakSession && weakController && WarningsAllowed(weakSession.get())) {
			weakController->showCloudPassword();
		}
	});
	box->addRow(object_ptr<Ui::FlatLabel>(box, state->sessions.value(), st::boxLabel));
	const auto sessions = box->addRow(object_ptr<Ui::LinkButton>(box,
		tr::lng_leemen_privacy_check_sessions(tr::now)));
	sessions->setClickedCallback([=] {
		if (!allowed() || !weakController) return;
		box->closeBox();
		if (weakSession && weakController && WarningsAllowed(weakSession.get())) {
			weakController->showSettings(Settings::SessionsId());
		}
	});
	const auto refresh = box->addRow(object_ptr<Ui::LinkButton>(box,
		tr::lng_leemen_privacy_check_refresh(tr::now)));
	const auto updateRefresh = [=] {
		refresh->setEnabled(!state->passwordPending && !state->sessionsPending);
	};
	const auto reload = [=] {
		if (!allowed() || state->passwordPending || state->sessionsPending) return;
		const auto request = ++state->request;
		state->passwordPending = state->sessionsPending = true;
		state->password = tr::lng_leemen_privacy_check_loading(tr::now);
		state->sessions = tr::lng_leemen_privacy_check_loading(tr::now);
		state->sessionsBaseline = session->api().authorizations().lastReceivedTime();
		updateRefresh();
		session->api().authorizations().reload();
		if (!weakBox || !allowed()) return;
		session->api().cloudPassword().reload();
		if (!weakBox || !allowed()) return;
		QTimer::singleShot(30000, box, [=] {
			if (!allowed() || state->request != request) return;
			if (state->passwordPending) {
				state->password = tr::lng_leemen_privacy_check_unavailable(tr::now);
				state->passwordPending = false;
			}
			if (state->sessionsPending) {
				state->sessions = tr::lng_leemen_privacy_check_unavailable(tr::now);
				state->sessionsPending = false;
			}
			updateRefresh();
		});
	};
	refresh->setClickedCallback(reload);
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	box->boxClosing() | rpl::on_next([=] { state->closing = true; }, box->lifetime());
	Core::App().screenshotProtection().addContentReason(rpl::single(true), box->lifetime());
	session->api().authorizations().listValue(
	) | rpl::skip(1) | rpl::on_next([=](const Api::Authorizations::List &list) {
		if (!allowed()) { box->closeBox(); return; }
		if (session->api().authorizations().lastReceivedTime() <= state->sessionsBaseline) return;
		const auto other = std::ranges::any_of(list, [](const Api::Authorizations::Entry &entry) {
			return entry.hash && entry.apiId != ApiId;
		});
		state->sessionsPending = false;
		state->sessions = other ? tr::lng_leemen_privacy_check_sessions_warning(tr::now)
			: tr::lng_leemen_privacy_check_sessions_ok(tr::now);
		updateRefresh();
	}, box->lifetime());
	const auto cachedPassword = session->api().cloudPassword().stateCurrent().has_value();
	session->api().cloudPassword().state(
	) | rpl::skip(cachedPassword ? 1 : 0) | rpl::on_next([=](const Core::CloudPasswordState &password) {
		if (!allowed()) { box->closeBox(); return; }
		state->passwordPending = false;
		state->password = password.hasPassword ? tr::lng_leemen_privacy_check_password_ok(tr::now)
			: tr::lng_leemen_privacy_check_password_warning(tr::now);
		updateRefresh();
	}, box->lifetime());
	const auto closeIfUnavailable = [=] {
		if (!allowed()) box->closeBox();
	};
	session->leemen().changes() | rpl::on_next(closeIfUnavailable, box->lifetime());
	session->domain().activeValue() | rpl::on_next(closeIfUnavailable, box->lifetime());
	Core::App().appDeactivatedValue() | rpl::on_next(closeIfUnavailable, box->lifetime());
	Core::App().passcodeLockValue() | rpl::on_next(closeIfUnavailable, box->lifetime());
	reload();
}

} // namespace

void ShowPrivateSpaceWarnings(not_null<Window::SessionController*> controller) {
	if (WarningsAllowed(&controller->session())) {
		controller->show(Box(WarningsBox, controller));
	}
}

} // namespace Leemen
