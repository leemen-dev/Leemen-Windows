#include "leemen/leemen_max_privacy_box.h"

#include "base/weak_ptr.h"
#include "core/application.h"
#include "core/core_screenshot_protection.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_private_space.h"
#include "leemen/sync_service.h"
#include "main/main_session.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"

#include <crl/crl_on_main.h>
#include <openssl/crypto.h>
#include <QtCore/QCryptographicHash>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

namespace Leemen {
namespace {

not_null<Ui::PasswordInput*> PasswordField(
		not_null<Ui::GenericBox*> box,
		rpl::producer<QString> placeholder) {
	const auto row = box->addRow(object_ptr<Ui::RpWidget>(box));
	row->resize(row->width(), st::defaultInputField.heightMin);
	const auto input = Ui::CreateChild<Ui::PasswordInput>(
		row, st::defaultInputField, std::move(placeholder));
	input->setMaxLength(4096);
	input->setInputMethodHints(Qt::ImhHiddenText | Qt::ImhNoPredictiveText);
	row->widthValue() | rpl::on_next([=](int width) {
		input->resize(width, input->height());
	}, input->lifetime());
	return input;
}

void PrivacyBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller,
		bool changePassword) {
	struct State {
		rpl::variable<QString> status;
		QString recoveryPhrase;
		std::uint64_t preparation = 0;
		bool busy = false;
		bool closing = false;
		bool committed = false;
		bool finished = false;
		bool hasRecovery = false;
	};
	const auto state = box->lifetime().make_state<State>();
	const auto session = &controller->session();
	const auto weak = base::make_weak(session);
	const auto weakBox = QPointer<Ui::GenericBox>(box.get());
	box->setTitle(changePassword
		? tr::lng_leemen_max_change() : tr::lng_leemen_max_enable());
	box->addRow(object_ptr<Ui::FlatLabel>(box,
		changePassword ? tr::lng_leemen_max_change_about()
			: tr::lng_leemen_max_about(), st::boxLabel));
	const auto password = PasswordField(box, tr::lng_leemen_max_password());
	const auto confirm = PasswordField(box, tr::lng_leemen_max_confirm());
	const auto words = box->addRow(object_ptr<Ui::FlatLabel>(
		box, tr::lng_leemen_max_recovery_pending(), st::boxLabel));
	const auto copy = box->addRow(object_ptr<Ui::LinkButton>(
		box, tr::lng_leemen_max_copy(tr::now)));
	copy->setEnabled(false);
	const auto saved = box->addRow(object_ptr<Ui::Checkbox>(
		box, tr::lng_leemen_max_saved(tr::now), false));
	saved->setEnabled(false);
	if (changePassword) {
		words->setText(tr::lng_leemen_max_recovery_unchanged(tr::now));
		copy->hide();
		saved->hide();
	}
	box->addRow(object_ptr<Ui::FlatLabel>(
		box, state->status.value(), st::boxLabel));
	Core::App().screenshotProtection().addContentReason(
		rpl::single(true), box->lifetime());
	const auto cancel = [=] {
		if (state->closing) {
			return;
		}
		state->closing = true;
		const auto preparation = std::exchange(state->preparation, 0);
		OPENSSL_cleanse(state->recoveryPhrase.data(),
			state->recoveryPhrase.size() * sizeof(QChar));
		state->recoveryPhrase.clear();
		if (weak && !state->committed && (state->busy || preparation)) {
			weak->leemen().syncService().cancelPrivacyPreparation(preparation);
		}
	};
	box->boxClosing() | rpl::on_next([=] {
		cancel();
		if (weakBox) {
			password->clear();
			confirm->clear();
			words->setText(QString());
		}
	}, box->lifetime());
	box->lifetime().add(cancel);
	copy->setClickedCallback([=] {
		if (!state->hasRecovery || state->closing) {
			return;
		}
		const auto text = state->recoveryPhrase;
		const auto digest = QCryptographicHash::hash(text.toUtf8(), QCryptographicHash::Sha256);
		QGuiApplication::clipboard()->setText(text);
		QTimer::singleShot(60000, qApp, [digest] {
			const auto clipboard = QGuiApplication::clipboard();
			if (QCryptographicHash::hash(clipboard->text().toUtf8(), QCryptographicHash::Sha256)
				== digest) {
				clipboard->clear();
			}
		});
		if (weakBox) {
			state->status = tr::lng_leemen_max_copied(tr::now);
		}
	});
	const auto complete = crl::guard(box, [=](bool success) {
		state->busy = false;
		state->preparation = 0;
		state->committed = success;
		state->finished = true;
		if (success) {
			OPENSSL_cleanse(state->recoveryPhrase.data(),
				state->recoveryPhrase.size() * sizeof(QChar));
			state->recoveryPhrase.clear();
			state->hasRecovery = false;
			words->setText(QString());
			copy->setEnabled(false);
			saved->setEnabled(false);
			state->status = tr::lng_leemen_max_done(tr::now);
		} else {
			state->status = tr::lng_leemen_max_failed(tr::now);
		}
	});
	const auto submit = [=] {
		if (!weak || state->busy || state->closing || state->finished
			|| !weak->leemen().active()) {
			return;
		}
		auto &sync = weak->leemen().syncService();
		if (state->preparation) {
			if (!changePassword && !saved->checked()) {
				state->status = tr::lng_leemen_max_save_first(tr::now);
				return;
			}
			state->busy = true;
			state->status = tr::lng_leemen_max_saving(tr::now);
			const auto preparation = state->preparation;
			const auto accepted = changePassword
				? sync.commitPassphraseChange(preparation, complete)
				: sync.commitMaximum(preparation, true, complete);
			if (!accepted && weakBox) {
				sync.cancelPrivacyPreparation(preparation);
				if (weakBox) {
					complete(false);
				}
			}
			return;
		}
		auto text = password->getLastText();
		auto repeated = confirm->getLastText();
		const auto matches = (text == repeated);
		repeated.fill(QChar(0));
		auto encoded = text.toUtf8();
		const auto tooLong = encoded.size() > 4096;
		OPENSSL_cleanse(encoded.data(), encoded.size());
		encoded.clear();
		if (text.size() < 8 || tooLong || !matches) {
			state->status = matches ? tr::lng_leemen_max_format(tr::now)
				: tr::lng_leemen_max_mismatch(tr::now);
			text.fill(QChar(0));
			return;
		}
		password->clear();
		confirm->clear();
		password->setEnabled(false);
		confirm->setEnabled(false);
		state->busy = true;
		state->status = tr::lng_leemen_max_preparing(tr::now);
		const auto prepared = crl::guard(box, [=](std::optional<std::uint64_t> id) {
			state->busy = false;
			state->preparation = id.value_or(0);
			state->status = id ? tr::lng_leemen_max_confirm_change(tr::now)
				: tr::lng_leemen_max_failed(tr::now);
			password->setEnabled(!id);
			confirm->setEnabled(!id);
		});
		const auto accepted = changePassword
			? sync.preparePassphraseChange(text, prepared)
			: sync.prepareMaximum(text, crl::guard(box,
				[=](std::optional<SyncService::MaximumPreparation> value) {
					prepared(value ? std::make_optional(value->id) : std::nullopt);
					if (value && weakBox && !state->closing) {
						state->hasRecovery = true;
						state->recoveryPhrase = std::move(value->recoveryPhrase);
						words->setText(state->recoveryPhrase);
						copy->setEnabled(true);
						saved->setEnabled(true);
						state->status = tr::lng_leemen_max_recovery_about(tr::now);
					}
				}));
		text.fill(QChar(0));
		if (!accepted && weakBox) {
			prepared(std::nullopt);
		}
	};
	QObject::connect(password, &Ui::PasswordInput::submitted, box,
		[=] { confirm->setFocus(); });
	QObject::connect(confirm, &Ui::PasswordInput::submitted, box, submit);
	box->addButton(tr::lng_leemen_sync_continue(), submit);
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	box->setFocusCallback([=] { password->setFocus(); });
}

} // namespace

void ShowMaximumPrivacy(not_null<Window::SessionController*> controller) {
	auto &space = controller->session().leemen();
	if (space.active() && space.syncEnabled() && space.syncService().projection()) {
		controller->show(Box(PrivacyBox, controller, space.syncService().maxMode()));
	}
}

} // namespace Leemen
