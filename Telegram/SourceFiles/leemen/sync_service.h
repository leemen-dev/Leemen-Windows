#pragma once

#include "leemen/sync_coordinator.h"
#include "leemen/sync_backend.h"
#include "leemen/security_policy.h"
#include "leemen/sync_session_snapshot.h"

#include <rpl/producer.h>
#include <QtCore/QByteArray>
#include <QtCore/QObject>
#include <QtCore/QString>

#include <memory>

namespace Main {
class Session;
} // namespace Main

namespace Leemen {

class SyncService final : public QObject {
public:
	enum class State {
		Idle,
		Authorizing,
		NeedsConsent,
		FetchingKey,
		NeedsPassphrase,
		Reading,
		Ready,
		Writing,
		Blocked,
		AccountDeleted,
	};
	enum class Error {
		None,
		Transport,
		Authorization,
		GenerationChanged,
		InvalidData,
		UnsupportedSchema,
		ConflictLimit,
		InvalidPassphrase,
		AuthorizationChanged,
		ResetUncertain,
		ResetConfirmed,
	};
	enum class MetadataStatus { Unknown, Loading, Ready, Failed };
	enum class ConsentStatus { Unknown, Required, Accepted };
	using ResetState = Sync::LocalResetState;
	struct MaximumPreparation {
		std::uint64_t id = 0;
		QString recoveryPhrase;
	};

	explicit SyncService(not_null<Main::Session*> session);
	~SyncService();

	void start();
	void refresh();
	void stop();
	void lockMax();
	void unlockMax(const QString &passphrase, bool recovery = false);
	bool acceptTerms(const QString &locale, Fn<void(bool)> done);
	[[nodiscard]] ConsentStatus consentStatus() const;
	[[nodiscard]] bool needsTermsConsent() const;
	[[nodiscard]] bool acceptingTerms() const;
	// A false return rejects the operation without calling its completion.
	bool prepareMaximum(
		const QString &passphrase,
		Fn<void(std::optional<MaximumPreparation>)> done);
	bool commitMaximum(
		std::uint64_t id,
		bool recoverySaved,
		Fn<void(bool)> done);
	bool preparePassphraseChange(
		const QString &passphrase,
		Fn<void(std::optional<std::uint64_t>)> done);
	bool commitPassphraseChange(std::uint64_t id, Fn<void(bool)> done);
	bool downgradePrivacy(bool serverKeyStorageAccepted, Fn<void(bool)> done);
	bool resetPrivateSpace(const QString &confirmation, Fn<void(bool)> done);
	bool completeLocalReset();
	[[nodiscard]] ResetState resetState() const;
	void cancelPrivacyPreparation(std::uint64_t id = 0);
	[[nodiscard]] bool privacyOperationBusy() const;
	bool submit(Sync::FilterBlob filter, Sync::ContentBlob content);
	void discardPendingMutation();
	[[nodiscard]] State state() const;
	[[nodiscard]] Error error() const;
	[[nodiscard]] bool linked() const;
	[[nodiscard]] bool maxMode() const;
	[[nodiscard]] MetadataStatus metadataStatus() const;
	[[nodiscard]] const Sync::Backend::MeReply *me() const;
	[[nodiscard]] std::optional<std::int64_t> metadataReceivedAt() const;
	[[nodiscard]] Security::PremiumSnapshot premium() const;
	[[nodiscard]] const Sync::SyncPair *projection() const;
	[[nodiscard]] const Sync::SyncPair *pendingMutation() const;
	[[nodiscard]] rpl::producer<> changes() const;
	[[nodiscard]] QByteArray serialize() const;
	bool restore(const QByteArray &serialized);

private:
	struct Data;
	const std::unique_ptr<Data> _data;
};

} // namespace Leemen
