#include "leemen/leemen_entry_shortcut.h"

#include "base/weak_ptr.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "core/shortcuts.h"
#include "lang/lang_keys.h"
#include "leemen/leemen_private_space.h"
#include "leemen/leemen_private_space_box.h"
#include "leemen/security_policy.h"
#include "main/main_session.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/checkbox.h"
#include "ui/widgets/labels.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include <QtCore/QCryptographicHash>
#include <QtGui/QGuiApplication>
#include <QtGui/QKeySequence>

#include "styles/style_layers.h"

namespace Leemen {
namespace {

constexpr auto kVisibleKey = "leemen.entry_visible";
constexpr auto kTestedKeysKey = "leemen.entry_tested_shortcuts";

std::vector<QKeySequence> EntryKeys() {
	auto result = std::vector<QKeySequence>();
	for (const auto &[keys, commands] : Shortcuts::KeysCurrents()) {
		if (commands.size() == 1 && commands.contains(Shortcuts::Command::LeemenPrivateSpace)) {
			result.push_back(keys);
		}
	}
	return result;
}

QByteArray KeysFingerprint() {
	auto keys = QByteArray();
	for (const auto &sequence : EntryKeys()) {
		keys += sequence.toString(QKeySequence::PortableText).toUtf8() + '\n';
	}
	return keys.isEmpty() ? QByteArray()
		: QCryptographicHash::hash(keys, QCryptographicHash::Sha256);
}

bool KeysTested() {
	const auto fingerprint = KeysFingerprint();
	return !fingerprint.isEmpty()
		&& fingerprint == Core::App().settings().readPref<QByteArray>(kTestedKeysKey);
}

void EntryBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto weak = base::make_weak(controller.get());
	box->setTitle(tr::lng_leemen_entry_settings());
	auto labels = QStringList();
	for (const auto &sequence : EntryKeys()) {
		labels.push_back(sequence.toString(QKeySequence::NativeText));
	}
	box->addRow(object_ptr<Ui::FlatLabel>(box,
		tr::lng_leemen_entry_about(lt_shortcut, rpl::single(labels.isEmpty()
			? tr::lng_leemen_entry_unassigned(tr::now) : labels.join(u", "_q))), st::boxLabel));
	const auto visible = box->addRow(object_ptr<Ui::Checkbox>(
		box, tr::lng_leemen_entry_visible(tr::now), PrivateSpaceEntryVisible()));
	const auto status = box->addRow(object_ptr<Ui::FlatLabel>(box,
		KeysTested() ? tr::lng_leemen_entry_tested() : tr::lng_leemen_entry_test_required(),
		st::boxLabel));
	visible->checkedChanges() | rpl::on_next([=](bool value) {
		if (!weak || !controller->session().leemen().active()) {
			return;
		}
		if (!value && !KeysTested()) {
			visible->setChecked(true);
			status->setText(tr::lng_leemen_entry_test_required(tr::now));
			return;
		}
		Core::App().settings().writePref<bool>(kVisibleKey, value);
		Core::App().saveSettingsDelayed();
	}, box->lifetime());
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

} // namespace

bool PrivateSpaceEntryVisible() {
	return Security::IsEntryButtonVisible(
		Core::App().settings().readPref<bool>(kVisibleKey, true),
		!EntryKeys().empty(),
		KeysTested());
}

bool HandlePrivateSpaceShortcut() {
	if (Core::App().passcodeLocked()
		|| QGuiApplication::applicationState() != Qt::ApplicationActive) {
		return false;
	}
	const auto window = Core::App().activeWindow();
	const auto controller = window ? window->sessionController() : nullptr;
	if (!controller) {
		return false;
	}
	auto &space = controller->session().leemen();
	if (!space.configured() && !PrivateSpace::EnrollmentEnabled()) {
		return false;
	}
	Core::App().settings().writePref<QByteArray>(kTestedKeysKey, KeysFingerprint());
	Core::App().saveSettingsDelayed();
	if (space.active()) {
		space.lock(true);
	} else {
		ShowPrivateSpace(controller);
	}
	return true;
}

void ShowPrivateSpaceEntrySettings(not_null<Window::SessionController*> controller) {
	if (controller->session().leemen().active()) {
		controller->show(Box(EntryBox, controller));
	}
}

} // namespace Leemen
