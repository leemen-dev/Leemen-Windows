#include "leemen/leemen_private_space_box.h"

#include "base/weak_ptr.h"
#include "core/application.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_account_box.h"
#include "leemen/leemen_entry_shortcut.h"
#include "leemen/leemen_max_privacy_box.h"
#include "leemen/leemen_onboarding_box.h"
#include "leemen/leemen_privacy_actions_box.h"
#include "leemen/leemen_privacy_warning_box.h"
#include "leemen/leemen_private_accounts.h"
#include "leemen/leemen_private_accounts_box.h"
#include "leemen/leemen_private_space.h"
#include "leemen/sync_peer_id.h"
#include "leemen/sync_service.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "ui/boxes/confirm_box.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/labels.h"
#include "ui/basic_click_handlers.h"
#include "window/window_session_controller.h"

#include <crl/crl_on_main.h>
#include <QtCore/QPointer>
#include <QtGui/QGuiApplication>

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

namespace Leemen {
namespace {

void SyncBox(not_null<Ui::GenericBox*> box, not_null<Window::SessionController*> controller);

bool CurrentForegroundSession(not_null<Main::Session*> session) {
	return session->domain().started()
		&& &session->domain().active() == &session->account()
		&& session->account().maybeSession() == session
		&& PrivateAccountContentAllowed(session)
		&& QGuiApplication::applicationState() == Qt::ApplicationActive
		&& !Core::App().passcodeLocked();
}

not_null<Ui::PasswordInput*> AddPinInput(
		not_null<Ui::GenericBox*> box,
		rpl::producer<QString> placeholder,
		int maximum = 12) {
	const auto row = box->addRow(object_ptr<Ui::RpWidget>(box));
	row->resize(row->width(), st::defaultInputField.heightMin);
	const auto input = Ui::CreateChild<Ui::PasswordInput>(
		row,
		st::defaultInputField,
		std::move(placeholder));
	input->setMaxLength(maximum);
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
		not_null<Window::SessionController*> controller,
		bool create) {
	struct State {
		rpl::variable<QString> error;
		std::uint64_t request = 0;
		bool busy = false;
		bool closing = false;
	};
	const auto session = &controller->session();
	const auto weakController = base::make_weak(controller.get());
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	const auto state = box->lifetime().make_state<State>();
	const auto weakSession = base::make_weak(session);
	const auto enrolled = session->leemen().configured();
	const auto synced = session->leemen().syncEnabled()
		&& (create || session->leemen().usesSyncedPin());
	box->setTitle(create
		? tr::lng_leemen_pin_create()
		: tr::lng_leemen_unlock());
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		synced ? tr::lng_leemen_synced_pin_about()
			: create ? tr::lng_leemen_local_preview() : tr::lng_leemen_pin_prompt(),
		st::boxLabel));
	const auto input = AddPinInput(box,
		synced ? tr::lng_leemen_synced_pin() : tr::lng_leemen_pin(),
		synced ? 6 : 12);
	const auto confirm = create
		? AddPinInput(box, tr::lng_leemen_pin_confirm(), synced ? 6 : 12).get()
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
			|| (create && enrolled && !space.active() && !space.needsPinSetup())
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
		auto done = [=](bool success) {
			if (success) {
				const auto navigate = !create || (weakBox && !state->closing);
				if (weakBox) {
					state->request = 0;
					box->closeBox();
				}
				if (navigate && weakController && weakSession
					&& &weakController->session() == weakSession.get()
					&& CurrentForegroundSession(weakSession.get())
					&& (create ? weakSession->leemen().configured()
						: weakSession->leemen().managementAllowed())) {
					ShowPrivateSpace(weakController.get());
				}
				return;
			}
			if (!weakBox || state->closing) {
				return;
			}
			state->busy = false;
			state->request = 0;
			if (!weakSession) {
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
				? (synced ? tr::lng_leemen_synced_pin_format(tr::now)
					: tr::lng_leemen_pin_format(tr::now))
				: tr::lng_leemen_pin_wrong(tr::now);
			input->showError();
		};
		const auto request = create
			? space.setPin(pin, std::move(done))
			: space.unlock(pin, std::move(done));
		pin.fill(QChar(0));
		if (weakBox && !state->closing && state->busy) {
			state->request = request;
		}
	};
	box->addButton(create ? tr::lng_settings_save() : tr::lng_leemen_unlock(), submit);
	if (!create && session->leemen().syncEnabled()) {
		const auto reset = box->addRow(object_ptr<Ui::LinkButton>(
			box, tr::lng_leemen_reset(tr::now)));
		reset->setClickedCallback([=] {
			if (weakController) {
				ShowPrivateSpaceReset(weakController.get());
			}
		});
	}
	if (session->leemen().syncEnabled()
		&& session->leemen().syncService().linked()) {
		const auto deletion = box->addRow(object_ptr<Ui::LinkButton>(
			box, tr::lng_leemen_account_delete_link(tr::now)));
		deletion->setClickedCallback([=] {
			if (weakController) {
				ShowLeemenAccountDeletion(weakController.get());
			}
		});
	}
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

QString SyncStatus(not_null<Main::Session*> session) {
	const auto &sync = session->leemen().syncService();
	if (sync.deletingAccount()) {
		return tr::lng_leemen_account_delete_sending(tr::now);
	}
	if (sync.accountDeletionPending()) {
		return tr::lng_leemen_account_delete_pending(tr::now);
	}
	if (sync.resetState() == SyncService::ResetState::Pending) {
		return tr::lng_leemen_reset_uncertain(tr::now);
	}
	if (sync.error() == SyncService::Error::InvalidPassphrase) {
		return tr::lng_leemen_sync_passphrase_wrong(tr::now);
	}
	using State = SyncService::State;
	if (sync.state() == State::Blocked
		&& sync.error() == SyncService::Error::Transport
		&& sync.cachedProjection()) {
		return tr::lng_leemen_sync_cached(tr::now);
	}
	switch (sync.state()) {
	case State::Idle: return tr::lng_leemen_sync_idle(tr::now);
	case State::Authorizing: return tr::lng_leemen_sync_auth(tr::now);
	case State::FetchingKey: return tr::lng_leemen_sync_key(tr::now);
	case State::NeedsConsent: return sync.needsTermsConsent()
		? tr::lng_leemen_terms_about(tr::now)
		: tr::lng_leemen_terms_failed(tr::now);
	case State::NeedsPassphrase: return tr::lng_leemen_sync_passphrase_about(tr::now);
	case State::Reading: return tr::lng_leemen_sync_reading(tr::now);
	case State::Writing: return tr::lng_leemen_sync_writing(tr::now);
	case State::Ready: return tr::lng_leemen_sync_ready(tr::now);
	case State::AccountDeleted: return tr::lng_leemen_sync_deleted(tr::now);
	case State::Blocked: return sync.error() == SyncService::Error::InvalidPassphrase
		? tr::lng_leemen_sync_passphrase_wrong(tr::now)
		: tr::lng_leemen_sync_error(tr::now);
	}
	return tr::lng_leemen_sync_error(tr::now);
}

void SyncBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto weak = base::make_weak(controller.get());
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	const auto session = &controller->session();
	auto &space = session->leemen();
	box->setTitle(tr::lng_leemen_sync_title());
	const auto locale = (Lang::Id() == u"ru"_q) ? u"ru"_q : u"en"_q;
	const auto legalBase = u"https://leemen.app"_q
		+ (locale == u"ru"_q ? u"/ru/"_q : u"/"_q);
	const auto termsLink = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_terms_link(tr::now)));
	termsLink->setClickedCallback([=] { UrlClickHandler::Open(legalBase + u"terms"_q); });
	const auto privacyLink = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_privacy_link(tr::now)));
	privacyLink->setClickedCallback([=] { UrlClickHandler::Open(legalBase + u"privacy"_q); });
	if (!space.syncEnabled()) {
		box->addRow(object_ptr<Ui::FlatLabel>(
			box, tr::lng_leemen_sync_about(), st::boxLabel));
		box->addButton(tr::lng_leemen_sync_connect(), [=] {
			if (weak && session->leemen().enableSync()) {
				if (weakBox) {
					weakBox->closeBox();
				}
				if (weak) {
					controller->show(Box(SyncBox, controller));
				}
			}
		});
		box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
		return;
	}
	const auto label = box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		rpl::single(SyncStatus(session)) | rpl::then(
			space.changes() | rpl::map([=] { return SyncStatus(session); })),
		st::boxLabel));
	const auto row = box->addRow(object_ptr<Ui::RpWidget>(box));
	row->resize(row->width(), st::defaultInputField.heightMin);
	const auto passphrase = Ui::CreateChild<Ui::PasswordInput>(
		row, st::defaultInputField, tr::lng_leemen_sync_passphrase());
	passphrase->setMaxLength(4096);
	row->widthValue() | rpl::on_next([=](int width) {
		passphrase->resize(width, passphrase->height());
	}, passphrase->lifetime());
	const auto recovery = box->addRow(object_ptr<Ui::Checkbox>(
		box, tr::lng_leemen_sync_use_recovery(tr::now), false));
	const auto crossBorder = box->addRow(object_ptr<Ui::FlatLabel>(
		box, tr::lng_leemen_terms_cross_border(), st::boxLabel));
	const auto acceptedTerms = box->addRow(object_ptr<Ui::Checkbox>(
		box, tr::lng_leemen_terms_accept(tr::now), false));
	const auto reset = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_reset(tr::now)));
	reset->setClickedCallback([=] {
		if (weak) {
			ShowPrivateSpaceReset(controller);
		}
	});
	const auto deletion = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_account_delete_link(tr::now)));
	deletion->setClickedCallback([=] {
		if (weak) {
			ShowLeemenAccountDeletion(controller);
		}
	});
	const auto consentBusy = box->lifetime().make_state<bool>(false);
	const auto submit = [=] {
		if (!weak) {
			return;
		}
		auto &sync = session->leemen().syncService();
		if (sync.state() == SyncService::State::Ready) {
			box->closeBox();
			if (weak) {
				ShowPrivateSpace(controller);
			}
		} else if (sync.state() == SyncService::State::NeedsConsent) {
			if (sync.consentStatus() == SyncService::ConsentStatus::Unknown) {
				sync.refresh();
				return;
			}
			if (!acceptedTerms->checked() || *consentBusy) {
				return;
			}
			*consentBusy = true;
			acceptedTerms->setEnabled(false);
			label->setText(tr::lng_leemen_terms_saving(tr::now));
			const auto complete = crl::guard(box, [=](bool success) {
				*consentBusy = false;
				acceptedTerms->setEnabled(true);
				if (!success) {
					label->setText(tr::lng_leemen_terms_failed(tr::now));
				}
			});
			if (!sync.acceptTerms(locale, complete) && weakBox) {
				complete(false);
			}
		} else if (sync.state() == SyncService::State::NeedsPassphrase) {
			auto text = passphrase->getLastText();
			passphrase->clear();
			sync.unlockMax(text, recovery->checked());
			text.fill(QChar(0));
		} else if (sync.state() == SyncService::State::Blocked
			|| sync.state() == SyncService::State::Idle) {
			sync.start();
		}
	};
	const auto update = [=] {
		const auto &sync = session->leemen().syncService();
		reset->setVisible(sync.linked() && !sync.accountDeletionPending());
		deletion->setVisible(sync.linked());
		const auto needed = sync.state() == SyncService::State::NeedsPassphrase;
		passphrase->setEnabled(needed);
		recovery->setEnabled(needed);
		row->setVisible(needed);
		recovery->setVisible(needed);
		const auto consent = sync.state() == SyncService::State::NeedsConsent
			&& sync.needsTermsConsent();
		acceptedTerms->setVisible(consent);
		acceptedTerms->setEnabled(consent && !*consentBusy);
		crossBorder->setVisible(consent && sync.me()
			&& sync.me()->account.kzConsentRequired);
	};
	update();
	space.changes() | rpl::on_next(update, label->lifetime());
	QObject::connect(passphrase, &Ui::PasswordInput::submitted, box, submit);
	box->addButton(tr::lng_leemen_sync_continue(), submit);
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

void PinTimeoutBox(
		not_null<Ui::GenericBox*> box,
		not_null<Main::Session*> session) {
	const auto weak = base::make_weak(session);
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	box->setTitle(tr::lng_leemen_pin_timeout());
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		tr::lng_leemen_pin_timeout_about(),
		st::boxLabel));
	const auto current = session->leemen().pinTimeoutMinutes();
	const auto group = std::make_shared<Ui::RadiobuttonGroup>(current);
	for (const auto minutes : { 0, 1, 5, 15, 60 }) {
		box->addRow(object_ptr<Ui::Radiobutton>(
			box,
			group,
			minutes,
			minutes
				? tr::lng_minutes(tr::now, lt_count, minutes)
				: tr::lng_leemen_pin_always(tr::now)));
	}
	box->addButton(tr::lng_settings_save(), [=] {
		if (weak && weak->leemen().active()) {
			weak->leemen().setPinTimeoutMinutes(group->current());
		}
		if (weakBox) {
			weakBox->closeBox();
		}
	});
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
}

void PremiumBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto weak = base::make_weak(controller.get());
	const auto session = &controller->session();
	box->setTitle(tr::lng_leemen_premium());
	box->addRow(object_ptr<Ui::FlatLabel>(
		box, tr::lng_leemen_premium_about(), st::boxLabel));
	const auto status = [=] {
		const auto &space = session->leemen();
		const auto access = space.syncEnabled()
			? session->leemen().syncService().premium().access
			: Security::PremiumAccess::Unknown;
		return (access == Security::PremiumAccess::Active)
			? tr::lng_leemen_premium_active(tr::now)
			: (access == Security::PremiumAccess::Inactive)
			? tr::lng_leemen_premium_inactive(tr::now)
			: tr::lng_leemen_premium_unknown(tr::now);
	};
	box->addRow(object_ptr<Ui::FlatLabel>(box,
		rpl::single(status()) | rpl::then(
			session->leemen().changes() | rpl::map(status)), st::boxLabel));
	box->addButton(tr::lng_leemen_premium_refresh(), [=] {
		if (weak && session->leemen().syncEnabled()) {
			session->leemen().syncService().refresh();
		}
	});
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

void LimitsBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto weak = base::make_weak(controller.get());
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	const auto session = &controller->session();
	box->setTitle(tr::lng_leemen_limits_title());
	const auto account = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_account_title(tr::now)));
	account->setClickedCallback([=] {
		if (weak) {
			ShowLeemenAccount(controller);
		}
	});
	box->addRow(object_ptr<Ui::FlatLabel>(
		box, tr::lng_leemen_limits_about(), st::boxLabel));
	const auto premium = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_premium(tr::now)));
	premium->setClickedCallback([=] {
		if (weak) {
			controller->show(Box(PremiumBox, controller));
		}
	});
	const auto accounts = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_accounts_title(tr::now)));
	accounts->setClickedCallback([=] {
		if (weak) {
			ShowPrivateAccounts(controller);
		}
	});
	for (const auto peerId : session->leemen().hiddenPeersForManagement()) {
		const auto peer = session->data().peerLoaded(peerId);
		const auto canonical = Sync::CanonicalPeerId(peerId);
		const auto name = peer ? peer->name()
			: tr::lng_leemen_unknown_chat(tr::now,
				lt_id, QString::number(canonical.value_or(0)));
		const auto reveal = box->addRow(object_ptr<Ui::LinkButton>(box, name));
		reveal->setClickedCallback([=] {
			if (!weak || !session->leemen().managementAllowed()) {
				return;
			}
			controller->show(Ui::MakeConfirmBox({
				.text = tr::lng_leemen_reveal_confirm(lt_chat, rpl::single(name)),
				.confirmed = [=](Fn<void()> close) {
					close();
					if (weak && session->leemen().setHidden(peerId, false)) {
						ShowPrivateSpace(controller);
					}
				},
				.confirmText = tr::lng_leemen_reveal_chat(),
			}));
		});
	}
	box->addButton(tr::lng_leemen_sync_continue(), [=] {
		box->closeBox();
		if (weak) {
			ShowPrivateSpace(controller);
		}
	});
	box->addButton(tr::lng_leemen_lock(), [=] {
		if (weak) {
			session->leemen().lock(true);
		}
		if (weakBox) {
			weakBox->closeBox();
		}
	});
}

void ManageBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto session = &controller->session();
	const auto weak = base::make_weak(controller.get());
	box->setTitle(tr::lng_leemen_private_space());
	if (session->leemen().syncEnabled()) {
		const auto account = box->addRow(object_ptr<Ui::LinkButton>(
			box, tr::lng_leemen_account_title(tr::now)));
		account->setClickedCallback([=] {
			if (weak) {
				ShowLeemenAccount(controller);
			}
		});
	}
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		tr::lng_leemen_active_about(),
		st::boxLabel));
	const auto privacyCheck = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_privacy_check(tr::now)));
	privacyCheck->setClickedCallback([=] {
		if (weak) {
			ShowPrivateSpaceWarnings(controller);
		}
	});
	const auto guide = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_tour_again(tr::now)));
	guide->setClickedCallback([=] {
		if (weak) {
			ShowPrivateSpaceOnboarding(controller);
		}
	});
	const auto sync = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_sync_title(tr::now)));
	sync->setClickedCallback([=] {
		if (weak) {
			controller->show(Box(SyncBox, controller));
		}
	});
	const auto premium = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_premium(tr::now)));
	premium->setClickedCallback([=] {
		if (weak) {
			controller->show(Box(PremiumBox, controller));
		}
	});
	const auto change = box->addRow(object_ptr<Ui::LinkButton>(
		box,
		tr::lng_leemen_pin_change(tr::now)));
	change->setClickedCallback([=] {
		if (weak && session->leemen().active()) {
			controller->show(Box(PinBox, controller, true));
		}
	});
	if (session->leemen().syncEnabled()) {
		const auto maximum = box->addRow(object_ptr<Ui::LinkButton>(box,
			session->leemen().syncService().maxMode()
				? tr::lng_leemen_max_change(tr::now) : tr::lng_leemen_max_enable(tr::now)));
		maximum->setClickedCallback([=] {
			if (weak) {
				ShowMaximumPrivacy(controller);
			}
		});
		const auto actions = box->addRow(object_ptr<Ui::LinkButton>(
			box, tr::lng_leemen_privacy_actions(tr::now)));
		actions->setClickedCallback([=] {
			if (weak) {
				ShowPrivacyActions(controller);
			}
		});
	}
	const auto accounts = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_accounts_title(tr::now)));
	accounts->setClickedCallback([=] {
		if (weak) {
			ShowPrivateAccounts(controller);
		}
	});
	const auto timeout = box->addRow(object_ptr<Ui::LinkButton>(
		box,
		tr::lng_leemen_pin_timeout(tr::now)));
	timeout->setClickedCallback([=] {
		if (weak && session->leemen().active()) {
			controller->show(Box(PinTimeoutBox, session));
		}
	});
	const auto entry = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_entry_settings(tr::now)));
	entry->setClickedCallback([=] {
		if (weak) {
			ShowPrivateSpaceEntrySettings(controller);
		}
	});
	const auto screenshots = box->addRow(object_ptr<Ui::Checkbox>(
		box,
		tr::lng_leemen_allow_screenshots(tr::now),
		session->leemen().screenshotsAllowed()));
	screenshots->checkedChanges() | rpl::on_next([=](bool allowed) {
		if (weak) {
			session->leemen().setScreenshotsAllowed(allowed);
		}
	}, screenshots->lifetime());
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
		session->leemen().lock(true);
	});
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	box->setShowFinishedCallback([=] {
		box->setShowFinishedCallback(nullptr);
		if (weak) {
			MaybeShowPrivateSpaceOnboarding(controller);
		}
	});
}

} // namespace

void ShowPrivateSpace(not_null<Window::SessionController*> controller) {
	auto &space = controller->session().leemen();
	if (space.damaged()) {
		controller->show(Ui::MakeInformBox(tr::lng_leemen_storage_error()));
	} else if (space.syncEnabled() && !space.syncService().projection()) {
		controller->show(Box(SyncBox, controller));
	} else if (space.needsPinSetup()) {
		controller->show(Box(PinBox, controller, true));
	} else if (space.active() || space.unlockWithinGrace()
		|| (space.managementAllowed() && space.requiresLimitResolution())) {
		controller->show(space.requiresLimitResolution()
			? Box(LimitsBox, controller)
			: Box(ManageBox, controller));
	} else if (!space.configured() && PrivateSpace::EnrollmentEnabled()) {
		controller->show(Box(SyncBox, controller));
	} else if (space.configured()) {
		controller->show(Box(
			PinBox,
			controller,
			!space.configured()));
	}
}

void ShowPrivateSpaceLimit(not_null<Window::SessionController*> controller) {
	controller->show(Box(PremiumBox, controller));
}

} // namespace Leemen
