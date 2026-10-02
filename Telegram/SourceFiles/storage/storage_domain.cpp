/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/storage_domain.h"

#include "core/version.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/serialize_common.h"
#include "mtproto/mtproto_config.h"
#include "main/main_domain.h"
#include "main/main_account.h"
#include "leemen/leemen_private_accounts.h"
#include "base/random.h"

#include <QtCore/QFileInfo>

namespace Storage {
namespace {

using namespace details;

[[nodiscard]] QString BaseGlobalPath() {
	return cWorkingDir() + u"tdata/"_q;
}

[[nodiscard]] QString ComputeKeyName(const QString &dataName) {
	// We dropped old test authorizations when migrated to multi auth.
	//return "key_" + dataName + (cTestMode() ? "[test]" : "");
	return "key_" + dataName;
}

} // namespace

Domain::Domain(not_null<Main::Domain*> owner, const QString &dataName)
: _owner(owner)
, _dataName(dataName) {
}

Domain::~Domain() = default;

StartResult Domain::start(const QByteArray &passcode) {
	const auto modern = startModern(passcode);
	if (modern == StartModernResult::Success) {
		if (_oldVersion < AppVersion) {
			writeAccounts();
		}
		return StartResult::Success;
	} else if (modern == StartModernResult::IncorrectPasscode) {
		return StartResult::IncorrectPasscode;
	} else if (modern == StartModernResult::CorruptPrivateAccounts) {
		return StartResult::CorruptPrivateAccounts;
	}
	auto legacy = std::make_unique<Main::Account>(_owner, _dataName, 0);
	const auto result = legacy->legacyStart(passcode);
	if (result == StartResult::Success) {
		_oldVersion = legacy->local().oldMapVersion();
		startWithSingleAccount(passcode, std::move(legacy));
	}
	return result;
}

void Domain::startAdded(
		not_null<Main::Account*> account,
		std::unique_ptr<MTP::Config> config) {
	Expects(_localKey != nullptr);

	account->prepareToStartAdded(_localKey);
	account->start(std::move(config));
}

void Domain::startWithSingleAccount(
		const QByteArray &passcode,
		std::unique_ptr<Main::Account> account) {
	Expects(account != nullptr);

	if (auto localKey = account->local().peekLegacyLocalKey()) {
		_localKey = std::move(localKey);
		encryptLocalKey(passcode);
		account->start(nullptr);
	} else {
		generateLocalKey();
		account->start(account->prepareToStart(_localKey));
	}
	_owner->accountAddedInStorage(Main::Domain::AccountWithIndex{
		.account = std::move(account)
	});
	writeAccounts();
}

void Domain::generateLocalKey() {
	Expects(_localKey == nullptr);
	Expects(_passcodeKeySalt.isEmpty());
	Expects(_passcodeKeyEncrypted.isEmpty());

	auto pass = QByteArray(MTP::AuthKey::kSize, Qt::Uninitialized);
	auto salt = QByteArray(LocalEncryptSaltSize, Qt::Uninitialized);
	base::RandomFill(pass.data(), pass.size());
	base::RandomFill(salt.data(), salt.size());
	_localKey = CreateLocalKey(pass, salt);

	encryptLocalKey(QByteArray());
}

void Domain::encryptLocalKey(const QByteArray &passcode) {
	_passcodeKeySalt.resize(LocalEncryptSaltSize);
	base::RandomFill(_passcodeKeySalt.data(), _passcodeKeySalt.size());
	_passcodeKey = CreateLocalKey(passcode, _passcodeKeySalt);

	EncryptedDescriptor passKeyData(MTP::AuthKey::kSize);
	_localKey->write(passKeyData.stream);
	_passcodeKeyEncrypted = PrepareEncrypted(passKeyData, _passcodeKey);
	_hasLocalPasscode = !passcode.isEmpty();
}

Domain::StartModernResult Domain::startModern(
		const QByteArray &passcode) {
	const auto name = ComputeKeyName(_dataName);

	FileReadDescriptor keyData;
	if (!ReadFile(keyData, name, BaseGlobalPath())) {
		const auto base = BaseGlobalPath() + name;
		if (QFileInfo::exists(base + 's') || QFileInfo::exists(base + '0') || QFileInfo::exists(base + '1')) {
			_owner->privateAccounts().blockCorruptedStartup();
			return StartModernResult::CorruptPrivateAccounts;
		}
		return StartModernResult::Empty;
	}
	if (std::size_t(keyData.data.size()) > Leemen::kMaxPrivateAccountsBytes + 4096) {
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}
	LOG(("App Info: reading accounts info..."));

	QByteArray salt, keyEncrypted, infoEncrypted;
	keyData.stream >> salt >> keyEncrypted >> infoEncrypted;
	if (!CheckStreamStatus(keyData.stream) || !keyData.stream.atEnd()) {
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}

	if (salt.size() != LocalEncryptSaltSize) {
		LOG(("App Error: bad salt in info file, size: %1").arg(salt.size()));
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}
	_passcodeKey = CreateLocalKey(passcode, salt);

	EncryptedDescriptor keyInnerData, info;
	if (!DecryptLocal(keyInnerData, keyEncrypted, _passcodeKey)) {
		LOG(("App Info: could not decrypt pass-protected key from info file, "
			"maybe bad password..."));
		return StartModernResult::IncorrectPasscode;
	}
	auto key = Serialize::read<MTP::AuthKey::Data>(keyInnerData.stream);
	if (keyInnerData.stream.status() != QDataStream::Ok
		|| !keyInnerData.stream.atEnd()) {
		LOG(("App Error: could not read pass-protected key from info file"));
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}
	_localKey = std::make_shared<MTP::AuthKey>(key);

	_passcodeKeyEncrypted = keyEncrypted;
	_passcodeKeySalt = salt;
	_hasLocalPasscode = !passcode.isEmpty();

	if (!DecryptLocal(info, infoEncrypted, _localKey)) {
		LOG(("App Error: could not decrypt info."));
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}
	if (std::size_t(info.data.size()) > Leemen::kMaxPrivateAccountsBytes + 128) {
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}
	LOG(("App Info: reading encrypted info..."));
	auto count = qint32();
	info.stream >> count;
	if (count <= 0 || count > Main::Domain::kPremiumMaxAccounts) {
		LOG(("App Error: bad accounts count: %1").arg(count));
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}

	_oldVersion = keyData.version;
	auto indices = std::vector<qint32>();
	for (auto i = 0; i != count; ++i) {
		auto index = qint32();
		info.stream >> index;
		indices.push_back(index);
	}
	auto selected = std::optional<qint32>();
	if (!info.stream.atEnd()) {
		auto index = qint32();
		info.stream >> index;
		selected = index;
	}
	auto privateAccounts = QByteArray();
	if (!info.stream.atEnd()) info.stream >> privateAccounts;
	if (info.stream.status() != QDataStream::Ok || !info.stream.atEnd()
		|| !_owner->privateAccounts().restore(privateAccounts)) {
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}

	auto tried = base::flat_set<int>();
	auto sessions = base::flat_set<uint64>();
	struct PreparedAccount {
		int index = 0;
		std::unique_ptr<Main::Account> account;
		std::unique_ptr<MTP::Config> config;
	};
	auto prepared = std::vector<PreparedAccount>();
	auto identities = std::vector<std::uint64_t>();
	auto active = 0;
	for (auto i = 0; i != count; ++i) {
		const auto index = indices[i];
		if (index >= 0
			&& index < Main::Domain::kPremiumMaxAccounts
			&& tried.emplace(index).second) {
			auto account = std::make_unique<Main::Account>(
				_owner,
				_dataName,
				index);
			auto config = account->prepareToStart(_localKey);
			const auto sessionId = account->willHaveSessionUniqueId(
				config.get());
			if (!sessions.contains(sessionId)
				&& (sessionId || (sessions.empty() && i + 1 == count)
					|| _owner->privateAccounts().configured())) {
				if (sessions.empty()) {
					active = index;
				}
				prepared.push_back({ index, std::move(account), std::move(config) });
				identities.push_back(sessionId);
				sessions.emplace(sessionId);
			}
		}
	}
	if (sessions.empty()) {
		LOG(("App Error: no accounts read."));
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}
	if (!_owner->privateAccounts().startupAllowed(identities)) {
		_owner->privateAccounts().blockCorruptedStartup();
		return StartModernResult::CorruptPrivateAccounts;
	}
	for (auto &entry : prepared) {
		entry.account->start(std::move(entry.config));
		_owner->accountAddedInStorage({ entry.index, std::move(entry.account) });
	}

	if (selected) active = *selected;
	_owner->activateFromStorage(active);

	Ensures(!sessions.empty());
	return StartModernResult::Success;
}

void Domain::writeAccounts(bool sync) {
	Expects(!_owner->accounts().empty());

	const auto path = BaseGlobalPath();
	if (!QDir().exists(path)) {
		QDir().mkpath(path);
	}

	FileWriteDescriptor key(ComputeKeyName(_dataName), path, sync);
	key.writeData(_passcodeKeySalt);
	key.writeData(_passcodeKeyEncrypted);

	const auto &list = _owner->accounts();

	auto keySize = sizeof(qint32) + sizeof(qint32) * list.size();

	EncryptedDescriptor keyData(keySize);
	keyData.stream << qint32(list.size());
	for (const auto &[index, account] : list) {
		keyData.stream << qint32(index);
	}
	keyData.stream << qint32(_owner->activeForStorage());
	keyData.stream << _owner->privateAccounts().serialize();
	key.writeEncrypted(keyData, _localKey);
}

bool Domain::writePrivateAccountsSync(const QByteArray &expected) {
	writeAccounts(true);
	auto file = FileReadDescriptor();
	if (!ReadFile(file, ComputeKeyName(_dataName), BaseGlobalPath())) return false;
	auto salt = QByteArray();
	auto key = QByteArray();
	auto encrypted = QByteArray();
	file.stream >> salt >> key >> encrypted;
	auto info = EncryptedDescriptor();
	if (file.stream.status() != QDataStream::Ok || !DecryptLocal(info, encrypted, _localKey)) return false;
	auto count = qint32();
	info.stream >> count;
	if (count <= 0 || count > Main::Domain::kPremiumMaxAccounts) return false;
	for (auto i = 0; i != count; ++i) {
		auto index = qint32();
		info.stream >> index;
	}
	auto active = qint32();
	auto actual = QByteArray();
	info.stream >> active >> actual;
	return info.stream.status() == QDataStream::Ok && info.stream.atEnd() && actual == expected;
}

void Domain::startFromScratch() {
	startWithSingleAccount(
		QByteArray(),
		std::make_unique<Main::Account>(_owner, _dataName, 0));
}

bool Domain::checkPasscode(const QByteArray &passcode) const {
	Expects(!_passcodeKeySalt.isEmpty());
	Expects(_passcodeKey != nullptr);

	const auto checkKey = CreateLocalKey(passcode, _passcodeKeySalt);
	return checkKey->equals(_passcodeKey);
}

void Domain::setPasscode(const QByteArray &passcode) {
	Expects(!_passcodeKeySalt.isEmpty());
	Expects(_localKey != nullptr);

	encryptLocalKey(passcode);
	writeAccounts();

	_passcodeKeyChanged.fire({});
}

int Domain::oldVersion() const {
	return _oldVersion;
}

void Domain::clearOldVersion() {
	_oldVersion = 0;
}

rpl::producer<> Domain::localPasscodeChanged() const {
	return _passcodeKeyChanged.events();
}

bool Domain::hasLocalPasscode() const {
	return _hasLocalPasscode;
}

} // namespace Storage
