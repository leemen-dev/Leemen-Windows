#include "leemen/leemen_account_box.h"

#include "base/weak_ptr.h"
#include "core/application.h"
#include "core/core_screenshot_protection.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_max_privacy_box.h"
#include "leemen/leemen_privacy_actions_box.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/leemen_private_space.h"
#include "leemen/sync_service.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "ui/basic_click_handlers.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"

#include <algorithm>
#include <crl/crl_on_main.h>
#include <QtCore/QDateTime>
#include <QtCore/QPointer>
#include <QtGui/QGuiApplication>

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

namespace Leemen {
namespace {

constexpr auto kDevicePageSize = 25;

bool AccountViewAllowed(not_null<Main::Session*> session) {
	const auto &space = session->leemen();
	return session->domain().started()
		&& &session->domain().active() == &session->account()
		&& session->account().maybeSession() == session
		&& QGuiApplication::applicationState() == Qt::ApplicationActive
		&& !Core::App().passcodeLocked()
		&& PrivateAccountContentAllowed(session)
		&& space.syncEnabled()
		&& session->leemen().syncService().linked()
		&& (space.managementAllowed() || space.needsPinSetup());
}

QString DateText(std::int64_t milliseconds) {
	const auto value = QDateTime::fromMSecsSinceEpoch(milliseconds);
	return milliseconds > 0 && value.isValid()
		? langDateTimeFull(value) : tr::lng_leemen_account_date_unknown(tr::now);
}

QString PremiumText(not_null<SyncService*> sync) {
	const auto premium = sync->premium();
	if (sync->metadataStatus() != SyncService::MetadataStatus::Ready
		|| premium.access == Security::PremiumAccess::Unknown) {
		return tr::lng_leemen_premium_unknown(tr::now);
	} else if (premium.access == Security::PremiumAccess::Inactive) {
		return tr::lng_leemen_premium_inactive(tr::now);
	} else if (premium.displayUntilMs >= Security::kPerpetualPremiumUntilMs) {
		return tr::lng_leemen_account_premium_perpetual(tr::now);
	}
	return tr::lng_leemen_account_premium_until(
		tr::now, lt_date, DateText(premium.displayUntilMs));
}

QString PlatformText(const std::string &value) {
	if (value == "android") return u"Android"_q;
	if (value == "ios") return u"iOS"_q;
	if (value == "windows") return u"Windows"_q;
	if (value == "macos" || value == "mac") return u"macOS"_q;
	if (value == "linux") return u"Linux"_q;
	return tr::lng_leemen_account_platform_other(tr::now);
}

QString PromoError(const Sync::Backend::Failure &failure) {
	if (failure.code == "promo_not_found") return tr::lng_leemen_promo_not_found(tr::now);
	if (failure.code == "promo_expired") return tr::lng_leemen_promo_expired(tr::now);
	if (failure.code == "promo_max_uses_reached") return tr::lng_leemen_promo_used_up(tr::now);
	if (failure.code == "promo_already_redeemed") return tr::lng_leemen_promo_already_used(tr::now);
	if (failure.kind == Sync::Backend::FailureKind::RateLimited) return tr::lng_leemen_promo_rate_limited(tr::now);
	return tr::lng_leemen_promo_failed(tr::now);
}

void AccountBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	struct State {
		rpl::variable<QString> status;
		QPointer<Ui::RoundButton> redeem;
		std::optional<std::int64_t> metadataBeforeRedeem;
		int deviceLimit = kDevicePageSize;
		bool busy = false;
		bool redeemed = false;
		bool sawMetadataLoading = false;
		bool closing = false;
		Fn<void()> refresh;
	};
	const auto session = &controller->session();
	const auto weakSession = base::make_weak(session);
	const auto weakController = base::make_weak(controller.get());
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	const auto state = box->lifetime().make_state<State>();
	box->setTitle(tr::lng_leemen_account_title());
	const auto premium = box->addRow(object_ptr<Ui::FlatLabel>(
		box, tr::lng_leemen_premium_unknown(), st::boxLabel));
	box->addRow(object_ptr<Ui::FlatLabel>(box,
		tr::lng_leemen_account_devices(), st::boxLabel));
	const auto devices = box->addRow(object_ptr<Ui::VerticalLayout>(box));
	const auto code = box->addRow(object_ptr<Ui::InputField>(
		box, st::defaultInputField, tr::lng_leemen_promo_code()));
	code->setMaxLength(64);
	code->setInputMethodHints(Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase);
	box->addRow(object_ptr<Ui::FlatLabel>(box, state->status.value(), st::boxLabel));
	Core::App().screenshotProtection().addContentReason(rpl::single(true), box->lifetime());
	box->boxClosing() | rpl::on_next([=] {
		state->closing = true;
		premium->setText(QString());
		state->status = QString();
		code->clear();
		devices->clear();
	}, box->lifetime());
	state->refresh = [=] {
		if (state->closing) return;
		if (!weakSession || !AccountViewAllowed(session)) {
			box->closeBox();
			return;
		}
		auto &sync = session->leemen().syncService();
		const auto metadataStatus = sync.metadataStatus();
		premium->setText(PremiumText(&sync));
		devices->clear();
		if (metadataStatus != SyncService::MetadataStatus::Ready || !sync.me()) {
			devices->add(object_ptr<Ui::FlatLabel>(devices,
				metadataStatus == SyncService::MetadataStatus::Loading
					? tr::lng_leemen_account_loading() : tr::lng_leemen_account_unavailable(), st::boxLabel));
		} else {
			// Copy server metadata before building widgets that can emit UI events.
			const auto values = sync.me()->devices;
			if (values.empty()) {
				devices->add(object_ptr<Ui::FlatLabel>(devices,
					tr::lng_leemen_account_devices_empty(), st::boxLabel));
			}
			const auto count = std::min(int(values.size()), state->deviceLimit);
			for (auto i = 0; i != count; ++i) {
				const auto &device = values[i];
				const auto name = device.name && !device.name->empty()
					? QString::fromStdString(*device.name)
					: tr::lng_leemen_account_device_unnamed(tr::now);
				const auto text = name + '\n' + PlatformText(device.platform)
					+ '\n' + tr::lng_leemen_account_last_seen(
						tr::now, lt_date, DateText(device.lastSeenAtMs));
				devices->add(object_ptr<Ui::FlatLabel>(devices, rpl::single(text), st::boxLabel));
			}
			if (count < int(values.size())) {
				const auto more = devices->add(object_ptr<Ui::SettingsButton>(
					devices, tr::lng_leemen_account_devices_more()));
				more->setClickedCallback([=] {
					state->deviceLimit += kDevicePageSize;
					state->refresh();
				});
			}
		}
		if (state->redeemed && metadataStatus == SyncService::MetadataStatus::Loading) {
			state->sawMetadataLoading = true;
		}
		if (state->redeemed && metadataStatus == SyncService::MetadataStatus::Ready
			&& (state->sawMetadataLoading || sync.metadataReceivedAt() != state->metadataBeforeRedeem)) {
			state->status = tr::lng_leemen_promo_done(tr::now);
		} else if (state->redeemed && metadataStatus == SyncService::MetadataStatus::Failed) {
			state->status = tr::lng_leemen_promo_status_unavailable(tr::now);
		}
		const auto enabled = !state->busy && !sync.redeemingPromo();
		code->setEnabled(enabled);
		if (state->redeem) state->redeem->setEnabled(enabled);
	};
	const auto submit = [=] {
		if (!weakSession || state->closing || state->busy || !AccountViewAllowed(session)) return;
		auto text = code->getLastText();
		if (text.isEmpty()) {
			code->showError();
			return;
		}
		auto &sync = session->leemen().syncService();
		state->busy = true;
		state->redeemed = false;
		state->sawMetadataLoading = false;
		state->metadataBeforeRedeem = sync.metadataReceivedAt();
		state->status = tr::lng_leemen_promo_redeeming(tr::now);
		code->clear();
		code->setEnabled(false);
		if (state->redeem) state->redeem->setEnabled(false);
		const auto accepted = sync.redeemPromo(text, crl::guard(box, [=](bool success) {
			if (state->closing || !weakSession || !AccountViewAllowed(session)) return;
			state->busy = false;
			state->redeemed = success;
			state->status = success ? tr::lng_leemen_promo_refreshing(tr::now)
				: PromoError(session->leemen().syncService().promoFailure());
			state->refresh();
		}));
		text.fill(QChar(0));
		if (!accepted && weakBox && weakSession && !state->closing) {
			state->busy = false;
			state->status = tr::lng_leemen_promo_failed(tr::now);
			state->refresh();
		}
	};
	state->redeem = box->addButton(tr::lng_leemen_promo_redeem(), submit);
	code->submits() | rpl::on_next(submit, code->lifetime());
	const auto refresh = box->addRow(object_ptr<Ui::LinkButton>(box,
		tr::lng_leemen_account_refresh(tr::now)));
	refresh->setClickedCallback([=] {
		if (weakSession && AccountViewAllowed(session)) {
			session->leemen().syncService().refreshAccountMetadata();
		}
	});
	const auto legalBase = u"https://leemen.app"_q
		+ (Lang::Id().startsWith(u"ru"_q) ? u"/ru/"_q : u"/"_q);
	const auto addLink = [&](QString title, QString path) {
		const auto link = box->addRow(object_ptr<Ui::LinkButton>(box, std::move(title)));
		link->setClickedCallback([=] {
			if (weakSession && AccountViewAllowed(session)) UrlClickHandler::Open(legalBase + path);
		});
	};
	addLink(tr::lng_leemen_terms_link(tr::now), u"terms"_q);
	addLink(tr::lng_leemen_privacy_link(tr::now), u"privacy"_q);
	addLink(tr::lng_leemen_account_delete_link(tr::now), u"delete-account"_q);
	if (session->leemen().active()) {
		const auto maximum = box->addRow(object_ptr<Ui::LinkButton>(box,
			session->leemen().syncService().maxMode()
				? tr::lng_leemen_max_change(tr::now) : tr::lng_leemen_max_enable(tr::now)));
		maximum->setClickedCallback([=] {
			if (weakSession && weakController && AccountViewAllowed(session)) ShowMaximumPrivacy(controller);
		});
		const auto actions = box->addRow(object_ptr<Ui::LinkButton>(box,
			tr::lng_leemen_privacy_actions(tr::now)));
		actions->setClickedCallback([=] {
			if (weakSession && weakController && AccountViewAllowed(session)) ShowPrivacyActions(controller);
		});
	} else {
		const auto reset = box->addRow(object_ptr<Ui::LinkButton>(box,
			tr::lng_leemen_reset(tr::now)));
		reset->setClickedCallback([=] {
			if (weakSession && weakController && AccountViewAllowed(session)) ShowPrivateSpaceReset(controller);
		});
	}
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	session->leemen().changes() | rpl::on_next([=] { state->refresh(); }, box->lifetime());
	session->domain().activeValue() | rpl::on_next([=](Main::Account *account) {
		if (account != &session->account()) box->closeBox();
	}, box->lifetime());
	session->account().sessionChanges() | rpl::on_next([=](Main::Session *current) {
		if (current != session) box->closeBox();
	}, box->lifetime());
	Core::App().appDeactivatedValue() | rpl::on_next([=](bool away) {
		if (away) box->closeBox();
	}, box->lifetime());
	Core::App().passcodeLockValue() | rpl::on_next([=](bool locked) {
		if (locked) box->closeBox();
	}, box->lifetime());
	state->refresh();
}

} // namespace

void ShowLeemenAccount(not_null<Window::SessionController*> controller) {
	if (AccountViewAllowed(&controller->session())) {
		controller->show(Box(AccountBox, controller));
	}
}

} // namespace Leemen
