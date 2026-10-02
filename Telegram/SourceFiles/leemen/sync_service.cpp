#include "leemen/sync_service.h"

#include "core/application.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "leemen/sync_backend.h"
#include "leemen/sync_crypto.h"
#include "leemen/max_privacy.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "mtproto/sender.h"

#include <crl/crl_async.h>
#include <crl/crl_on_main.h>
#include <openssl/crypto.h>
#include <rpl/event_stream.h>
#include <rpl/take.h>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtGui/QGuiApplication>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <set>
#include <utility>

namespace Leemen {
namespace {

namespace Backend = Sync::Backend;
using State = SyncService::State;
using Error = SyncService::Error;
using MetadataStatus = SyncService::MetadataStatus;
using ResetState = SyncService::ResetState;
using HttpDone = Fn<void(int, const QByteArray&)>;
enum class PrivacyOperation {
	Idle,
	PreparingMaximum,
	PreparedMaximum,
	PreparingPassword,
	PreparedPassword,
	CommittingMaximum,
	CommittingPassword,
	ReconcilingMaximum,
	ReconcilingPassword,
	CommittingDowngrade,
	ReconcilingDowngrade,
};

constexpr auto kRequestTimeout = 30000;
constexpr auto kPollInterval = 60000;

std::int64_t MonotonicNow() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string_view View(const QByteArray &bytes) {
	return { bytes.constData(), std::size_t(bytes.size()) };
}

std::string_view View(const Sync::SecretBytes &bytes) {
	const auto data = bytes.bytes();
	return { reinterpret_cast<const char*>(data.data()), data.size() };
}

void Wipe(QByteArray &bytes) {
	OPENSSL_cleanse(bytes.data(), bytes.size());
	bytes.clear();
}

QByteArray RecoveryBytes(const QString &phrase) {
	auto begin = qsizetype();
	auto end = phrase.size();
	while (begin < end && phrase[begin].unicode() <= 0x20) {
		++begin;
	}
	while (end > begin && phrase[end - 1].unicode() <= 0x20) {
		--end;
	}
	auto lower = phrase.mid(begin, end - begin).toLower();
	auto normalized = QString();
	normalized.reserve(lower.size());
	auto previousSpace = false;
	for (const auto ch : lower) {
		const auto code = ch.unicode();
		const auto space = code == 0x20 || (code >= 0x09 && code <= 0x0D);
		if (!space || !previousSpace) {
			normalized.append(space ? QChar(0x20) : ch);
		}
		previousSpace = space;
	}
	const auto result = normalized.toUtf8();
	OPENSSL_cleanse(lower.data(), lower.size() * sizeof(QChar));
	OPENSSL_cleanse(normalized.data(), normalized.size() * sizeof(QChar));
	return result;
}

struct HttpData {
	QByteArray bytes;
	bool tooLarge = false;
	~HttpData() {
		Wipe(bytes);
	}
};

std::optional<Sync::SecretBytes> InitData(const QString &resultUrl) {
	const auto url = QUrl(resultUrl);
	if (!url.isValid() || url.scheme() != u"https"_q
		|| url.host() != u"auth.leemen.app"_q
		|| !url.userInfo().isEmpty()) {
		return std::nullopt;
	}
	auto value = QByteArray();
	auto found = false;
	for (const auto &part : url.fragment(QUrl::FullyEncoded).toLatin1().split('&')) {
		if (part.startsWith("tgWebAppData=")) {
			if (found) {
				Wipe(value);
				return std::nullopt;
			}
			found = true;
			value = part.mid(13);
		}
	}
	if (value.isEmpty() || value.size() > 65536) {
		Wipe(value);
		return std::nullopt;
	}
	const auto hex = [](char ch) {
		return (ch >= '0' && ch <= '9')
			|| (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
	};
	for (auto i = qsizetype(); i < value.size(); ++i) {
		if (value[i] == '%') {
			if (i + 2 >= value.size() || !hex(value[i + 1]) || !hex(value[i + 2])) {
				Wipe(value);
				return std::nullopt;
			}
			i += 2;
		}
	}
	value.replace('+', ' ');
	auto decoded = QByteArray::fromPercentEncoding(value);
	Wipe(value);
	auto result = Sync::SecretBytes(std::size_t(decoded.size()));
	std::copy(decoded.begin(), decoded.end(), result.bytes().begin());
	Wipe(decoded);
	return result;
}

std::optional<std::string> KeyFingerprint(const Sync::SecretKey &key) {
	const auto bytes = Sync::MasterKeyFingerprint(key.bytes());
	if (!bytes) {
		return std::nullopt;
	}
	constexpr auto hex = "0123456789abcdef";
	auto result = std::string();
	result.reserve(bytes->size() * 2);
	for (const auto ch : *bytes) {
		result.push_back(hex[ch >> 4]);
		result.push_back(hex[ch & 15]);
	}
	return result;
}

bool SameMaximumKey(
		const Backend::MaximumPrivacyKey &a,
		const Backend::MaximumPrivacyKey &b) {
	return a.wrapVersion == b.wrapVersion
		&& a.wrappedPassword == b.wrappedPassword
		&& a.passwordSalt == b.passwordSalt
		&& a.wrappedRecovery == b.wrappedRecovery
		&& a.recoverySalt == b.recoverySalt;
}

} // namespace

struct SyncService::Data {
	explicit Data(SyncService *owner, not_null<Main::Session*> session);
	void watch();
	void cancel();
	bool publish(State next, Error problem = Error::None);
	void block(Error problem, bool deleted = false);
	void retryTransport();
	void failure(const Backend::Failure &failure);
	void http(
		const QByteArray &method,
		const QString &path,
		std::optional<Sync::SecretBytes> body,
		HttpDone done,
		bool authorized = true,
		Fn<void(Error)> failed = nullptr);
	void authorize();
	void requestInitData(not_null<UserData*> bot);
	void postAuth(Sync::SecretBytes initData);
	void fetchKey();
	bool fetchMe();
	void acceptMe(int status, const QByteArray &bytes);
	void failMe(Error error);
	bool acceptTerms(const QString &locale, Fn<void(bool)> done);
	void writeConsent();
	void finishConsent(bool accepted);
	void updatePremiumDeadline();
	bool canPreparePrivacy(bool maximum) const;
	bool preparePrivacy(
		const QString &passphrase,
		Fn<void(std::optional<SyncService::MaximumPreparation>)> maximumDone,
		Fn<void(std::optional<std::uint64_t>)> passwordDone);
	bool commitPrivacy(std::uint64_t id, bool maximum, Fn<void(bool)> done);
	void clearPrivacy();
	void privacyKeyChecked(int status, const QByteArray &bytes);
	void postPrivacy();
	bool downgradePrivacy(Fn<void(bool)> done);
	void postDowngrade();
	void reconcileDowngrade();
	void downgradeSucceeded(Sync::SecretKey key);
	bool beginReset(Fn<void(bool)> done);
	void postReset();
	void finishReset(bool confirmed, Error problem);
	void reconcilePrivacy();
	void privacySucceeded(Backend::MaximumPrivacyKey key);
	void privacyFailed(Error problem);
	bool privacyIsMaximum() const;
	bool privacyIsCommitting() const;
	void acceptKey(Backend::AccountKey key);
	bool acceptMasterKey(Sync::SecretKey key);
	bool canUnlockMaximum() const;
	void unlockMaximum(std::shared_ptr<Sync::SecretBytes> secret, bool recovery);
	void deriveMaximum(std::shared_ptr<Sync::SecretBytes> secret, bool recovery);
	void wrapDefault();
	void pull();
	void dispatch(std::vector<Sync::SyncRequest> requests);
	void prepareWrite(Sync::SyncRequest request);
	void sendWrite(const Sync::SyncRequest &request);
	void acceptBlob(const Sync::SyncRequest &request, Backend::RemoteBlob blob);
	void updateState();
	void keepPendingAndClose();
	QByteArray serialize() const;
	bool restore(const QByteArray &serialized);

	SyncService *owner = nullptr;
	not_null<Main::Session*> session;
	MTP::Sender api;
	QNetworkAccessManager network;
	QTimer mtpTimeout;
	QTimer poll;
	QTimer retry;
	QTimer premiumTimer;
	mtpRequestId mtpRequest = 0;
	int transportRetries = 0;
	std::set<QNetworkReply*> replies;
	std::uint64_t epoch = 0;
	bool enabled = false;
	bool maximumMode = false;
	bool authRetried = false;
	bool renewalRetried = false;
	bool wrapAttempted = false;
	bool transportRetryPending = false;
	State state = State::Idle;
	Error error = Error::None;
	MetadataStatus metadataStatus = MetadataStatus::Unknown;
	std::optional<Backend::MeReply> metadata;
	std::optional<std::int64_t> metadataReceivedAt;
	std::uint64_t metadataRequestId = 0;
	ConsentStatus consentStatus = ConsentStatus::Unknown;
	bool awaitingConsent = false;
	std::vector<Backend::ConsentType> consentWrites;
	std::string consentLocale;
	Fn<void(bool)> consentDone;
	Security::PremiumClock premiumClock;
	PrivacyOperation privacyOperation = PrivacyOperation::Idle;
	std::uint64_t privacyId = 0;
	std::optional<Sync::MaximumPrivacySetup> maximumPreparation;
	std::optional<Sync::PasswordWrapping> passwordPreparation;
	std::optional<Backend::MaximumPrivacyKey> privacyOriginalWrap;
	Fn<void(std::optional<SyncService::MaximumPreparation>)> maximumPrepared;
	Fn<void(std::optional<std::uint64_t>)> passwordPrepared;
	Fn<void(bool)> privacyCommitted;
	ResetState resetState = ResetState::None;
	bool resetAuthorizing = false;
	Fn<void(bool)> resetDone;
	Sync::SecretBytes token;
	std::optional<Sync::SecretKey> masterKey;
	std::optional<std::string> masterFingerprint;
	std::optional<Backend::MaximumPrivacyKey> maximumKey;
	std::optional<Backend::Generation> generation;
	std::optional<Backend::Bootstrap> bootstrap;
	Sync::SyncCoordinator coordinator;
	rpl::event_stream<> changes;
	rpl::lifetime lifetime;
};

SyncService::Data::Data(SyncService *owner, not_null<Main::Session*> session)
: owner(owner)
, session(session)
, api(&session->mtp()) {
	mtpTimeout.setSingleShot(true);
	QObject::connect(&mtpTimeout, &QTimer::timeout, owner, [=, this] {
		block(Error::Transport);
	});
	poll.setInterval(kPollInterval);
	QObject::connect(&poll, &QTimer::timeout, owner, [=, this] {
		if (QGuiApplication::applicationState() == Qt::ApplicationActive) {
			owner->refresh();
		}
	});
	retry.setSingleShot(true);
	QObject::connect(&retry, &QTimer::timeout, owner, [=, this] {
		retryTransport();
	});
	premiumTimer.setSingleShot(true);
	QObject::connect(&premiumTimer, &QTimer::timeout, owner, [=, this] {
		updatePremiumDeadline();
		publish(state, error);
	});
}

void SyncService::Data::watch() {
	const auto owner = this->owner;
	const auto session = this->session;
	Core::App().appDeactivatedValue() | rpl::on_next([=, this](bool away) {
		if (away) {
			owner->lockMax();
		} else if (enabled && state == State::Blocked && error == Error::Transport) {
			retryTransport();
		} else if (enabled) {
			owner->refresh();
		}
	}, lifetime);
	session->domain().activeValue() | rpl::on_next([=](Main::Account *account) {
		if (account != &session->account()) {
			owner->lockMax();
		}
	}, lifetime);
	session->account().sessionChanges(
	) | rpl::filter([=](Main::Session *value) {
		return value != session;
	}) | rpl::take(1) | rpl::on_next([=] {
		owner->stop();
	}, lifetime);
	Core::App().passcodeLockValue() | rpl::on_next([=](bool locked) {
		if (locked) {
			owner->lockMax();
		}
	}, lifetime);
}

void SyncService::Data::cancel() {
	++epoch;
	clearPrivacy();
	finishConsent(false);
	resetAuthorizing = false;
	if (auto done = std::exchange(resetDone, nullptr)) {
		crl::on_main([done = std::move(done)] { done(false); });
	}
	mtpTimeout.stop();
	poll.stop();
	retry.stop();
	transportRetryPending = false;
	if (metadataStatus == MetadataStatus::Loading) {
		metadataStatus = MetadataStatus::Failed;
	}
	if (mtpRequest) {
		api.request(std::exchange(mtpRequest, 0)).cancel();
	}
	for (const auto reply : std::exchange(replies, {})) {
		QObject::disconnect(reply, nullptr, owner, nullptr);
		reply->abort();
		reply->deleteLater();
	}
}

bool SyncService::Data::publish(State next, Error problem) {
	state = next;
	error = problem;
	const auto guard = QPointer<SyncService>(owner);
	const auto before = epoch;
	changes.fire({});
	return guard && guard->_data->epoch == before;
}

void SyncService::Data::keepPendingAndClose() {
	auto checkpoint = coordinator.checkpoint();
	coordinator.close();
	coordinator.restoreCheckpoint(std::move(checkpoint));
}

void SyncService::Data::block(Error problem, bool deleted) {
	cancel();
	bootstrap.reset();
	keepPendingAndClose();
	if (problem == Error::Authorization || problem == Error::GenerationChanged || deleted) {
		token.clear();
		masterKey.reset();
	}
	if (problem == Error::GenerationChanged || deleted) {
		premiumTimer.stop();
		premiumClock.clear();
		metadataStatus = MetadataStatus::Failed;
	}
	if (problem == Error::Transport && enabled && transportRetries < 3
		&& resetState == ResetState::None) {
		const auto delays = std::array{ 5000, 15000, 45000 };
		transportRetryPending = true;
		retry.start(delays[transportRetries++]);
	}
	publish(deleted ? State::AccountDeleted : State::Blocked, problem);
}

void SyncService::Data::retryTransport() {
	if (!enabled || !transportRetryPending
		|| state != State::Blocked || error != Error::Transport
		|| QGuiApplication::applicationState() != Qt::ApplicationActive
		|| (maximumMode && !canUnlockMaximum())) {
		return;
	}
	transportRetryPending = false;
	retry.stop();
	if (masterKey && !token.bytes().empty()) {
		pull();
	} else if (!token.bytes().empty()) {
		fetchKey();
	} else {
		authorize();
	}
}

void SyncService::Data::failure(const Backend::Failure &failure) {
	switch (failure.kind) {
	case Backend::FailureKind::AccountDeleted:
		block(Error::Authorization, true);
		return;
	case Backend::FailureKind::GenerationChanged:
		block(Error::GenerationChanged);
		return;
	case Backend::FailureKind::Unauthorized:
		if (generation && !renewalRetried) {
			renewalRetried = true;
			cancel();
			keepPendingAndClose();
			token.clear();
			masterKey.reset();
			bootstrap.reset();
			authorize();
		} else {
			block(Error::Authorization);
		}
		return;
	case Backend::FailureKind::Retryable:
	case Backend::FailureKind::RateLimited:
		block(Error::Transport);
		return;
	default:
		block(Error::InvalidData);
		return;
	}
}

void SyncService::Data::http(
		const QByteArray &method,
		const QString &path,
		std::optional<Sync::SecretBytes> body,
		HttpDone done,
		bool authorized,
		Fn<void(Error)> failed) {
	if (!enabled || (authorized && token.bytes().empty())) {
		if (failed) {
			failed(Error::Authorization);
		} else {
			block(Error::Authorization);
		}
		return;
	}
	const auto requestEpoch = epoch;
	auto request = QNetworkRequest(QUrl(u"https://api.leemen.app/v1/"_q + path));
	request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
	request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
	request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
	request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
	request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
	request.setTransferTimeout(kRequestTimeout);
	request.setRawHeader("Accept", "application/json");
	if (authorized) {
		const auto secret = View(token);
		auto header = QByteArray("Bearer ") + QByteArray(secret.data(), secret.size());
		request.setRawHeader("Authorization", header);
		Wipe(header);
	}
	auto payload = QByteArray();
	if (body) {
		const auto secret = View(*body);
		payload = QByteArray(secret.data(), secret.size());
		request.setHeader(QNetworkRequest::ContentTypeHeader, u"application/json"_q);
	}
	const auto reply = network.sendCustomRequest(request, method, payload);
	Wipe(payload);
	replies.emplace(reply);
	reply->setReadBufferSize(qint64(Backend::kMaxResponseBytes + 1));
	const auto data = std::make_shared<HttpData>();
	const auto collect = [=] {
		const auto remaining = qint64(Backend::kMaxResponseBytes) - data->bytes.size();
		if (remaining < 0) {
			data->tooLarge = true;
			return;
		}
		data->bytes.append(reply->read(remaining + 1));
		if (std::size_t(data->bytes.size()) > Backend::kMaxResponseBytes) {
			data->tooLarge = true;
			reply->abort();
		}
	};
	QObject::connect(reply, &QIODevice::readyRead, owner, collect);
	QObject::connect(reply, &QNetworkReply::metaDataChanged, owner, [=] {
		const auto length = reply->header(QNetworkRequest::ContentLengthHeader).toLongLong();
		if (length > qint64(Backend::kMaxResponseBytes)) {
			data->tooLarge = true;
			reply->abort();
		}
	});
	QObject::connect(reply, &QNetworkReply::finished, owner,
		[=, this, done = std::move(done), failed = std::move(failed)] {
			replies.erase(reply);
			reply->deleteLater();
			if (requestEpoch != epoch) {
				return;
			}
			collect();
			if (data->tooLarge) {
				if (failed) {
					failed(Error::InvalidData);
				} else {
					block(Error::InvalidData);
				}
				return;
			}
			const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
			if (!status || (status >= 200 && status < 300
				&& reply->error() != QNetworkReply::NoError)) {
				if (failed) {
					failed(Error::Transport);
				} else {
					block(Error::Transport);
				}
				return;
			}
			done(status, data->bytes);
		});
	QTimer::singleShot(kRequestTimeout, reply, [reply = QPointer<QNetworkReply>(reply)] {
		if (reply && !reply->isFinished()) {
			reply->abort();
		}
	});
}

void SyncService::Data::authorize() {
	if (!publish(State::Authorizing)) {
		return;
	}
	const auto requestEpoch = epoch;
	mtpTimeout.start(kRequestTimeout);
	mtpRequest = api.request(MTPcontacts_ResolveUsername(
		MTP_flags(0), MTP_string("leemen_auth_bot"), MTP_string()
	)).done([=, this](const MTPcontacts_ResolvedPeer &result) {
		if (requestEpoch != epoch) {
			return;
		}
		mtpRequest = 0;
		mtpTimeout.stop();
		result.match([&](const MTPDcontacts_resolvedPeer &data) {
			session->data().processUsers(data.vusers());
			session->data().processChats(data.vchats());
			const auto peer = session->data().peerLoaded(peerFromMTP(data.vpeer()));
			const auto bot = peer ? peer->asUser() : nullptr;
			if (!bot || !bot->isBot()) {
				block(Error::Authorization);
				return;
			}
			requestInitData(bot);
		});
	}).fail([=, this] {
		if (requestEpoch == epoch) {
			block(Error::Transport);
		}
	}).send();
}

void SyncService::Data::requestInitData(not_null<UserData*> bot) {
	const auto requestEpoch = epoch;
	mtpTimeout.start(kRequestTimeout);
	using Flag = MTPmessages_RequestWebView::Flag;
	mtpRequest = api.request(MTPmessages_RequestWebView(
		MTP_flags(Flag::f_url),
		bot->input(), bot->inputUser(),
		MTP_string("https://auth.leemen.app"),
		MTP_string(), MTP_dataJSON(MTP_string("{}")),
		MTP_string("tdesktop"), MTPInputReplyTo(), MTP_inputPeerEmpty()
	)).done([=, this](const MTPWebViewResult &result) {
		if (requestEpoch != epoch) {
			return;
		}
		mtpRequest = 0;
		mtpTimeout.stop();
		result.match([&](const MTPDwebViewResultUrl &data) {
			auto initData = InitData(qs(data.vurl()));
			if (!initData) {
				block(Error::Authorization);
				return;
			}
			postAuth(std::move(*initData));
		}, [&](const auto &) {
			block(Error::Authorization);
		});
	}).fail([=, this] {
		if (requestEpoch == epoch) {
			block(Error::Transport);
		}
	}).send();
}

void SyncService::Data::postAuth(Sync::SecretBytes initData) {
	auto body = Backend::EncodeAuthRequest(View(initData), generation);
	if (!body) {
		block(Error::InvalidData);
		return;
	}
	http("POST", u"auth/telegram"_q, std::move(body), [=, this](int status, const QByteArray &bytes) {
		auto result = Backend::ParseAuth(status, View(bytes));
		if (!result.value) {
			if (!authRetried && (result.failure.kind == Backend::FailureKind::InitDataInvalid
				|| result.failure.kind == Backend::FailureKind::InitDataReplayed)) {
				authRetried = true;
				authorize();
			} else {
				failure(result.failure);
			}
			return;
		}
		auto &auth = *result.value;
		if (generation && *generation != auth.generation) {
			block(Error::GenerationChanged);
			return;
		}
		generation = std::move(auth.generation);
		token = std::move(auth.token);
		maximumMode = auth.privacyMode == Backend::PrivacyMode::Maximum;
		bootstrap = std::move(auth.bootstrap);
		if (resetState != ResetState::None) {
			bootstrap.reset();
			if (resetAuthorizing) {
				postReset();
			} else {
				finishReset(false, Error::ResetUncertain);
			}
			return;
		}
		consentStatus = ConsentStatus::Unknown;
		awaitingConsent = true;
		if (!publish(State::NeedsConsent)) {
			return;
		}
		fetchMe();
	}, false);
}

void SyncService::Data::fetchKey() {
	if (consentStatus != ConsentStatus::Accepted || awaitingConsent) {
		return;
	}
	if (!publish(State::FetchingKey)) {
		return;
	}
	http("GET", u"account/key"_q, std::nullopt, [=, this](int status, const QByteArray &bytes) {
		auto result = Backend::ParseAccountKey(status, View(bytes));
		if (!result.value) {
			failure(result.failure);
		} else {
			acceptKey(std::move(*result.value));
		}
	});
}

bool SyncService::Data::fetchMe() {
	if (metadataStatus == MetadataStatus::Loading
		|| privacyOperation != PrivacyOperation::Idle
		|| !consentWrites.empty()) {
		return true;
	}
	const auto guard = QPointer<SyncService>(owner);
	const auto before = epoch;
	const auto requestId = ++metadataRequestId;
	metadataStatus = MetadataStatus::Loading;
	if (!publish(state, error)) {
		return false;
	}
	http("GET", u"me"_q, std::nullopt,
		[=, this](int status, const QByteArray &bytes) {
			if (metadataRequestId == requestId) {
				acceptMe(status, bytes);
			}
		}, true, [=, this](Error problem) {
			if (metadataRequestId == requestId) {
				failMe(problem);
			}
		});
	return guard && guard->_data->epoch == before;
}

void SyncService::Data::acceptMe(int status, const QByteArray &bytes) {
	auto result = Backend::ParseMe(status, View(bytes));
	if (!result.value) {
		metadataStatus = MetadataStatus::Failed;
		if (result.failure.kind == Backend::FailureKind::Unauthorized
			|| result.failure.kind == Backend::FailureKind::AccountDeleted
			|| result.failure.kind == Backend::FailureKind::GenerationChanged) {
			failure(result.failure);
		} else {
			failMe(Error::InvalidData);
		}
		return;
	}
	const auto &account = result.value->account;
	if (!generation || account.generation != *generation
		|| account.telegramUserId <= 0
		|| std::uint64_t(account.telegramUserId) != session->userId().bare) {
		metadataStatus = MetadataStatus::Failed;
		block(Error::GenerationChanged);
		return;
	}
	metadata = std::move(*result.value);
	metadataReceivedAt = MonotonicNow();
	metadataStatus = MetadataStatus::Ready;
	premiumClock.apply(*metadata, *metadataReceivedAt);
	updatePremiumDeadline();
	if (state == State::Ready) {
		renewalRetried = false;
	}
	const auto maximum = metadata->account.privacyMode == Backend::PrivacyMode::Maximum;
	if (!Backend::HasRequiredConsents(*metadata)) {
		cancel();
		keepPendingAndClose();
		masterKey.reset();
		bootstrap.reset();
		maximumMode = maximum;
		consentStatus = ConsentStatus::Required;
		awaitingConsent = true;
		publish(State::NeedsConsent);
		return;
	}
	consentStatus = ConsentStatus::Accepted;
	if (awaitingConsent) {
		awaitingConsent = false;
		finishConsent(true);
		if (maximum != maximumMode) {
			bootstrap.reset();
			maximumMode = maximum;
		}
		if (bootstrap) {
			acceptKey(std::move(bootstrap->key));
		} else {
			fetchKey();
		}
		return;
	}
	if (maximum != maximumMode) {
		cancel();
		keepPendingAndClose();
		masterKey.reset();
		bootstrap.reset();
		maximumMode = maximum;
		fetchKey();
	} else {
		publish(state, error);
	}
}

void SyncService::Data::failMe(Error problem) {
	metadataStatus = MetadataStatus::Failed;
	if (awaitingConsent) {
		finishConsent(false);
		consentStatus = ConsentStatus::Unknown;
		publish(State::NeedsConsent, problem);
	} else {
		publish(state, error);
	}
}

bool SyncService::Data::acceptTerms(const QString &locale, Fn<void(bool)> done) {
	if (!done || !enabled || token.bytes().empty() || !awaitingConsent
		|| consentStatus != ConsentStatus::Required || metadataStatus != MetadataStatus::Ready
		|| !metadata || consentDone || state != State::NeedsConsent
		|| resetState != ResetState::None || !canUnlockMaximum()
		|| (locale != u"ru"_q && locale != u"en"_q)) {
		return false;
	}
	const auto terms = Backend::ConsentType::Terms;
	const auto kz = Backend::ConsentType::KzCrossBorder;
	if (!Backend::HasCurrentConsent(*metadata, terms)) {
		consentWrites.push_back(terms);
	}
	if (metadata->account.kzConsentRequired && !Backend::HasCurrentConsent(*metadata, kz)) {
		consentWrites.push_back(kz);
	}
	consentLocale = locale.toStdString();
	consentDone = std::move(done);
	++metadataRequestId;
	if (publish(State::NeedsConsent)) {
		writeConsent();
	}
	return true;
}

void SyncService::Data::finishConsent(bool accepted) {
	consentWrites.clear();
	consentLocale.clear();
	if (auto done = std::exchange(consentDone, nullptr)) {
		crl::on_main([done = std::move(done), accepted] { done(accepted); });
	}
}

void SyncService::Data::writeConsent() {
	if (!consentDone || !awaitingConsent) {
		return;
	} else if (consentWrites.empty()) {
		fetchMe();
		return;
	}
	auto body = Backend::EncodeConsentRequest(consentWrites.front(), consentLocale);
	if (!body) {
		failMe(Error::InvalidData);
		return;
	}
	http("POST", u"consent"_q, std::move(body),
		[=, this](int status, const QByteArray &bytes) {
			const auto result = Backend::ParseOk(status, View(bytes));
			if (result.value) {
				consentWrites.erase(consentWrites.begin());
				writeConsent();
			} else if (status == 401) {
				failure(result.failure);
			} else {
				consentWrites.clear();
				fetchMe();
			}
		}, true, [=, this](Error) {
			consentWrites.clear();
			fetchMe();
		});
}

void SyncService::Data::updatePremiumDeadline() {
	premiumTimer.stop();
	const auto now = MonotonicNow();
	const auto value = premiumClock.snapshot(now);
	if (value.access == Security::PremiumAccess::Active && value.deadlineMonotonicMs) {
		const auto remaining = *value.deadlineMonotonicMs - now;
		premiumTimer.start(int(std::clamp(remaining, std::int64_t(1),
			std::int64_t(std::numeric_limits<int>::max()))));
	}
}

bool SyncService::Data::privacyIsMaximum() const {
	return privacyOperation == PrivacyOperation::PreparingMaximum
		|| privacyOperation == PrivacyOperation::PreparedMaximum
		|| privacyOperation == PrivacyOperation::CommittingMaximum
		|| privacyOperation == PrivacyOperation::ReconcilingMaximum;
}

bool SyncService::Data::privacyIsCommitting() const {
	return privacyOperation == PrivacyOperation::CommittingMaximum
		|| privacyOperation == PrivacyOperation::CommittingPassword
		|| privacyOperation == PrivacyOperation::ReconcilingMaximum
		|| privacyOperation == PrivacyOperation::ReconcilingPassword
		|| privacyOperation == PrivacyOperation::CommittingDowngrade
		|| privacyOperation == PrivacyOperation::ReconcilingDowngrade;
}

void SyncService::Data::clearPrivacy() {
	if (auto done = std::exchange(maximumPrepared, nullptr)) {
		crl::on_main([done = std::move(done)] { done(std::nullopt); });
	}
	if (auto done = std::exchange(passwordPrepared, nullptr)) {
		crl::on_main([done = std::move(done)] { done(std::nullopt); });
	}
	if (auto done = std::exchange(privacyCommitted, nullptr)) {
		crl::on_main([done = std::move(done)] { done(false); });
	}
	maximumPreparation.reset();
	passwordPreparation.reset();
	privacyOriginalWrap.reset();
	privacyOperation = PrivacyOperation::Idle;
}

bool SyncService::Data::canPreparePrivacy(bool maximum) const {
	return canUnlockMaximum() && state == State::Ready && masterKey
		&& resetState == ResetState::None
		&& !token.bytes().empty() && !coordinator.pendingMutation()
		&& privacyOperation == PrivacyOperation::Idle
		&& privacyId != std::numeric_limits<std::uint64_t>::max()
		&& (maximum ? !maximumMode : (maximumMode && maximumKey));
}

bool SyncService::Data::preparePrivacy(
		const QString &passphrase,
		Fn<void(std::optional<SyncService::MaximumPreparation>)> maximumDone,
		Fn<void(std::optional<std::uint64_t>)> passwordDone) {
	const auto maximum = bool(maximumDone);
	if ((!maximumDone && !passwordDone) || !canPreparePrivacy(maximum)
		|| std::size_t(passphrase.size()) > Sync::kMaxSecretBytes) {
		return false;
	}
	auto bytes = passphrase.toUtf8();
	if (bytes.isEmpty() || std::size_t(bytes.size()) > Sync::kMaxSecretBytes) {
		Wipe(bytes);
		return false;
	}
	auto secret = std::make_shared<Sync::SecretBytes>(std::size_t(bytes.size()));
	std::copy(bytes.begin(), bytes.end(), secret->bytes().begin());
	Wipe(bytes);
	auto key = std::make_shared<Sync::SecretKey>();
	std::copy(masterKey->bytes().begin(), masterKey->bytes().end(), key->bytes().begin());
	maximumPrepared = std::move(maximumDone);
	passwordPrepared = std::move(passwordDone);
	privacyOperation = maximum
		? PrivacyOperation::PreparingMaximum : PrivacyOperation::PreparingPassword;
	privacyOriginalWrap = maximum ? std::nullopt : maximumKey;
	++metadataRequestId;
	if (metadataStatus == MetadataStatus::Loading) {
		metadataStatus = MetadataStatus::Failed;
	}
	const auto id = ++privacyId;
	const auto before = epoch;
	const auto guard = QPointer<SyncService>(owner);
	poll.stop();
	if (!publish(state, error)) {
		return true;
	}
	crl::async([=] {
		auto setup = std::make_shared<std::optional<Sync::MaximumPrivacySetup>>();
		auto password = std::make_shared<std::optional<Sync::PasswordWrapping>>();
		if (maximum) {
			*setup = Sync::PrepareMaximumPrivacy(key->bytes(), View(*secret));
		} else {
			*password = Sync::PreparePasswordWrapping(key->bytes(), View(*secret));
		}
		key->clear();
		secret->clear();
		crl::on_main([=] {
			if (!guard || guard->_data->epoch != before
				|| guard->_data->privacyId != id) {
				return;
			}
			const auto data = guard->_data.get();
			if (!data->canUnlockMaximum()) {
				guard->cancelPrivacyPreparation(id);
				return;
			}
			if ((maximum && !*setup) || (!maximum && !*password)) {
				data->privacyFailed(Error::InvalidData);
				return;
			}
			if (maximum) {
				data->maximumPreparation = std::move(**setup);
				data->privacyOperation = PrivacyOperation::PreparedMaximum;
			} else {
				data->passwordPreparation = std::move(**password);
				data->privacyOperation = PrivacyOperation::PreparedPassword;
			}
			if (!data->publish(data->state, data->error)) {
				return;
			}
			if (maximum) {
				const auto phrase = View(data->maximumPreparation->recoveryPhrase);
				auto view = SyncService::MaximumPreparation{
					id, QString::fromUtf8(phrase.data(), phrase.size()) };
				const auto done = std::exchange(data->maximumPrepared, nullptr);
				done(std::move(view));
			} else {
				const auto done = std::exchange(data->passwordPrepared, nullptr);
				done(id);
			}
		});
	});
	return true;
}

bool SyncService::Data::commitPrivacy(
		std::uint64_t id,
		bool maximum,
		Fn<void(bool)> done) {
	const auto expected = maximum
		? PrivacyOperation::PreparedMaximum : PrivacyOperation::PreparedPassword;
	if (!done || id != privacyId || privacyOperation != expected
		|| !canUnlockMaximum() || state != State::Ready || !masterKey
		|| coordinator.pendingMutation()) {
		return false;
	}
	privacyCommitted = std::move(done);
	privacyOperation = maximum
		? PrivacyOperation::CommittingMaximum : PrivacyOperation::CommittingPassword;
	if (!publish(state, error)) {
		return true;
	}
	http("GET", u"account/key"_q, std::nullopt,
		[=, this](int status, const QByteArray &bytes) {
			privacyKeyChecked(status, bytes);
		});
	return true;
}

void SyncService::Data::privacyKeyChecked(int status, const QByteArray &bytes) {
	auto result = Backend::ParseAccountKey(status, View(bytes));
	if (!result.value) {
		failure(result.failure);
		return;
	}
	if (!canUnlockMaximum()) {
		owner->cancelPrivacyPreparation(privacyId);
		return;
	}
	if (privacyIsMaximum()) {
		const auto key = std::get_if<Backend::DefaultKey>(&*result.value);
		if (!key || !masterFingerprint || KeyFingerprint(key->masterKey) != masterFingerprint) {
			block(Error::GenerationChanged);
			return;
		}
	} else {
		const auto key = std::get_if<Backend::MaximumPrivacyKey>(&*result.value);
		if (!key || !privacyOriginalWrap || !SameMaximumKey(*key, *privacyOriginalWrap)) {
			masterKey.reset();
			block(Error::AuthorizationChanged);
			return;
		}
	}
	if (privacyOperation == PrivacyOperation::CommittingDowngrade) {
		postDowngrade();
	} else {
		postPrivacy();
	}
}

void SyncService::Data::postPrivacy() {
	const auto maximum = privacyIsMaximum();
	auto body = maximum && maximumPreparation
		? Backend::EncodeUpgradePrivacyRequest(
			maximumPreparation->password.wrapped, maximumPreparation->password.salt,
			maximumPreparation->recovery.wrapped, maximumPreparation->recovery.salt)
		: passwordPreparation && privacyOriginalWrap
		? Backend::EncodePasswordWrapRequest(passwordPreparation->wrapped,
			passwordPreparation->salt, privacyOriginalWrap->wrapVersion)
		: std::nullopt;
	if (!body) {
		privacyFailed(Error::InvalidData);
		return;
	}
	http(maximum ? "POST" : "PUT",
		maximum ? u"account/upgrade-privacy"_q : u"account/wrap-pw"_q,
		std::move(body), [=, this](int status, const QByteArray &bytes) {
			const auto result = Backend::ParseWrapReceipt(status, View(bytes));
			if (result.value && (maximum || (privacyOriginalWrap
				&& result.value->wrapVersion == privacyOriginalWrap->wrapVersion + 1))) {
				auto key = maximum
					? Backend::MaximumPrivacyKey{ maximumPreparation->password.wrapped,
						maximumPreparation->password.salt, maximumPreparation->recovery.wrapped,
						maximumPreparation->recovery.salt, result.value->wrapVersion }
					: *privacyOriginalWrap;
				if (!maximum) {
					key.wrappedPassword = passwordPreparation->wrapped;
					key.passwordSalt = passwordPreparation->salt;
					key.wrapVersion = result.value->wrapVersion;
				}
				privacySucceeded(std::move(key));
			} else if (status == 401) {
				failure(result.failure);
			} else if (status >= 400 && status < 500 && status != 409) {
				privacyFailed(Error::InvalidData);
			} else {
				reconcilePrivacy();
			}
		}, true, [=, this](Error) { reconcilePrivacy(); });
}

void SyncService::Data::reconcilePrivacy() {
	const auto maximum = privacyIsMaximum();
	privacyOperation = maximum
		? PrivacyOperation::ReconcilingMaximum : PrivacyOperation::ReconcilingPassword;
	http("GET", u"account/key"_q, std::nullopt,
		[=, this](int status, const QByteArray &bytes) {
			auto result = Backend::ParseAccountKey(status, View(bytes));
			const auto key = result.value
				? std::get_if<Backend::MaximumPrivacyKey>(&*result.value) : nullptr;
			auto expected = maximum && maximumPreparation
				? Backend::MaximumPrivacyKey{ maximumPreparation->password.wrapped,
					maximumPreparation->password.salt, maximumPreparation->recovery.wrapped,
					maximumPreparation->recovery.salt, key ? key->wrapVersion : 0 }
				: privacyOriginalWrap.value_or(Backend::MaximumPrivacyKey());
			if (!maximum && passwordPreparation) {
				expected.wrappedPassword = passwordPreparation->wrapped;
				expected.passwordSalt = passwordPreparation->salt;
				++expected.wrapVersion;
			}
			if (key && SameMaximumKey(*key, expected) && canUnlockMaximum()) {
				privacySucceeded(*key);
			} else {
				maximumMode = maximumMode || maximum;
				masterKey.reset();
				if (!result.value) {
					failure(result.failure);
				} else {
					block(Error::AuthorizationChanged);
				}
			}
		}, true, [=, this](Error problem) {
			maximumMode = maximumMode || maximum;
			masterKey.reset();
			block(problem);
		});
}

void SyncService::Data::privacySucceeded(Backend::MaximumPrivacyKey key) {
	const auto done = std::exchange(privacyCommitted, nullptr);
	clearPrivacy();
	maximumMode = true;
	maximumKey = std::move(key);
	crl::on_main([done] { done(true); });
	if (!canUnlockMaximum()) {
		owner->lockMax();
		return;
	}
	poll.start();
	if (publish(state)) {
		fetchMe();
	}
}

void SyncService::Data::privacyFailed(Error problem) {
	clearPrivacy();
	if (state == State::Ready) {
		poll.start();
	}
	publish(state, problem);
}

bool SyncService::Data::downgradePrivacy(Fn<void(bool)> done) {
	if (!done || !canPreparePrivacy(false)) {
		return false;
	}
	++privacyId;
	++metadataRequestId;
	if (metadataStatus == MetadataStatus::Loading) {
		metadataStatus = MetadataStatus::Failed;
	}
	privacyOriginalWrap = maximumKey;
	privacyCommitted = std::move(done);
	privacyOperation = PrivacyOperation::CommittingDowngrade;
	poll.stop();
	if (!publish(state, error)) {
		return true;
	}
	http("GET", u"account/key"_q, std::nullopt,
		[=, this](int status, const QByteArray &bytes) {
			privacyKeyChecked(status, bytes);
		});
	return true;
}

void SyncService::Data::postDowngrade() {
	auto body = masterKey
		? Backend::EncodeDefaultWrapRequest(masterKey->bytes()) : std::nullopt;
	if (!body) {
		privacyFailed(Error::InvalidData);
		return;
	}
	http("POST", u"account/downgrade-privacy"_q, std::move(body),
		[=, this](int status, const QByteArray &bytes) {
			const auto result = Backend::ParseWrapReceipt(status, View(bytes));
			if (status == 401) {
				failure(result.failure);
			} else if (status >= 400 && status < 500 && status != 409) {
				privacyFailed(Error::InvalidData);
			} else {
				reconcileDowngrade();
			}
		}, true, [=, this](Error) { reconcileDowngrade(); });
}

void SyncService::Data::reconcileDowngrade() {
	privacyOperation = PrivacyOperation::ReconcilingDowngrade;
	http("GET", u"account/key"_q, std::nullopt,
		[=, this](int status, const QByteArray &bytes) {
			auto result = Backend::ParseAccountKey(status, View(bytes));
			if (!result.value) {
				masterKey.reset();
				failure(result.failure);
				return;
			}
			if (auto key = std::get_if<Backend::DefaultKey>(&*result.value)) {
				if (masterFingerprint && KeyFingerprint(key->masterKey) == masterFingerprint) {
					downgradeSucceeded(std::move(key->masterKey));
				} else {
					block(Error::GenerationChanged);
				}
			} else if (const auto key = std::get_if<Backend::MaximumPrivacyKey>(&*result.value)
				; key && privacyOriginalWrap && SameMaximumKey(*key, *privacyOriginalWrap)) {
				privacyFailed(Error::ConflictLimit);
			} else {
				masterKey.reset();
				block(Error::AuthorizationChanged);
			}
		}, true, [=, this](Error problem) {
			masterKey.reset();
			block(problem);
		});
}

void SyncService::Data::downgradeSucceeded(Sync::SecretKey key) {
	const auto done = std::exchange(privacyCommitted, nullptr);
	clearPrivacy();
	maximumMode = false;
	maximumKey.reset();
	masterKey = std::move(key);
	poll.start();
	crl::on_main([done] { done(true); });
	if (publish(state)) {
		fetchMe();
	}
}

bool SyncService::Data::beginReset(Fn<void(bool)> done) {
	if (!done || !generation || !canUnlockMaximum()
		|| resetState == ResetState::Confirmed || resetDone
		|| privacyOperation != PrivacyOperation::Idle
		|| state == State::Authorizing || state == State::FetchingKey
		|| state == State::Reading || state == State::Writing) {
		return false;
	}
	cancel();
	keepPendingAndClose();
	token.clear();
	masterKey.reset();
	maximumKey.reset();
	bootstrap.reset();
	resetState = ResetState::Pending;
	resetAuthorizing = true;
	resetDone = std::move(done);
	authRetried = renewalRetried = false;
	if (!publish(State::Blocked, Error::ResetUncertain)) {
		return true;
	}
	authorize();
	return true;
}

void SyncService::Data::postReset() {
	resetAuthorizing = false;
	if (!canUnlockMaximum() || resetState != ResetState::Pending || !resetDone) {
		finishReset(false, Error::ResetUncertain);
		return;
	}
	constexpr auto bodyText = std::string_view("{\"confirm\":\"RESET\"}");
	auto body = Sync::SecretBytes(bodyText.size());
	std::copy(bodyText.begin(), bodyText.end(), body.bytes().begin());
	http("POST", u"security/reset-private-space"_q, std::move(body),
		[=, this](int status, const QByteArray &bytes) {
			const auto result = Backend::ParseOk(status, View(bytes));
			finishReset(result.value && *result.value,
				result.value && *result.value ? Error::ResetConfirmed : Error::ResetUncertain);
		}, true, [=, this](Error) {
			finishReset(false, Error::ResetUncertain);
		});
}

void SyncService::Data::finishReset(bool confirmed, Error problem) {
	const auto done = std::exchange(resetDone, nullptr);
	cancel();
	keepPendingAndClose();
	token.clear();
	masterKey.reset();
	maximumKey.reset();
	bootstrap.reset();
	resetState = confirmed ? ResetState::Confirmed : ResetState::Pending;
	if (done) {
		crl::on_main([done, confirmed] { done(confirmed); });
	}
	publish(State::Blocked, problem);
}

void SyncService::Data::acceptKey(Backend::AccountKey key) {
	if (consentStatus != ConsentStatus::Accepted || awaitingConsent) {
		return;
	}
	if (auto ready = std::get_if<Backend::DefaultKey>(&key)) {
		if (!acceptMasterKey(std::move(ready->masterKey))) {
			return;
		}
		maximumMode = false;
		maximumKey.reset();
		pull();
	} else if (auto maximum = std::get_if<Backend::MaximumPrivacyKey>(&key)) {
		maximumMode = true;
		maximumKey = *maximum;
		masterKey.reset();
		bootstrap.reset();
		publish(State::NeedsPassphrase);
	} else if (!wrapAttempted) {
		wrapDefault();
	} else {
		block(Error::InvalidData);
	}
}

bool SyncService::Data::acceptMasterKey(Sync::SecretKey key) {
	const auto fingerprint = KeyFingerprint(key);
	if (!fingerprint) {
		block(Error::InvalidData);
		return false;
	} else if (masterFingerprint && masterFingerprint != fingerprint) {
		block(Error::GenerationChanged);
		return false;
	}
	masterFingerprint = *fingerprint;
	masterKey = std::move(key);
	return true;
}

bool SyncService::Data::canUnlockMaximum() const {
	return enabled
		&& session->domain().started()
		&& &session->domain().active() == &session->account()
		&& session->account().maybeSession() == session
		&& QGuiApplication::applicationState() == Qt::ApplicationActive
		&& !Core::App().passcodeLocked();
}

void SyncService::Data::unlockMaximum(
		std::shared_ptr<Sync::SecretBytes> secret,
		bool recovery) {
	if (!canUnlockMaximum() || !publish(State::FetchingKey)) {
		return;
	}
	http("GET", u"account/key"_q, std::nullopt,
		[=, this](int status, const QByteArray &bytes) {
			auto result = Backend::ParseAccountKey(status, View(bytes));
			if (!result.value) {
				secret->clear();
				failure(result.failure);
				return;
			}
			if (!canUnlockMaximum()) {
				secret->clear();
				owner->lockMax();
				return;
			}
			if (const auto maximum = std::get_if<Backend::MaximumPrivacyKey>(
					&*result.value)) {
				maximumKey = *maximum;
				deriveMaximum(secret, recovery);
			} else {
				secret->clear();
				acceptKey(std::move(*result.value));
			}
		});
}

void SyncService::Data::deriveMaximum(
		std::shared_ptr<Sync::SecretBytes> secret,
		bool recovery) {
	if (!canUnlockMaximum() || !maximumKey) {
		return;
	}
	const auto material = *maximumKey;
	const auto before = epoch;
	const auto guard = QPointer<SyncService>(owner);
	crl::async([=] {
		auto wrapping = Sync::DeriveWrappingKey(View(*secret),
			recovery ? material.recoverySalt : material.passwordSalt);
		secret->clear();
		auto master = std::make_shared<std::optional<Sync::SecretKey>>(
			wrapping ? Sync::UnwrapMasterKey(
				recovery ? material.wrappedRecovery : material.wrappedPassword,
				wrapping->bytes()) : std::nullopt);
		crl::on_main([=] {
			if (!guard || guard->_data->epoch != before) {
				return;
			}
			if (!guard->_data->canUnlockMaximum()) {
				guard->lockMax();
			} else if (!*master) {
				guard->_data->publish(State::NeedsPassphrase, Error::InvalidPassphrase);
			} else if (guard->_data->acceptMasterKey(std::move(**master))) {
				guard->_data->pull();
			}
		});
	});
}

void SyncService::Data::wrapDefault() {
	if (consentStatus != ConsentStatus::Accepted || awaitingConsent) {
		return;
	}
	if (masterFingerprint || resetState != ResetState::None) {
		block(Error::GenerationChanged);
		return;
	}
	wrapAttempted = true;
	bootstrap.reset();
	auto key = Sync::RandomKey();
	if (!key) {
		block(Error::InvalidData);
		return;
	}
	auto proposed = std::make_shared<Sync::SecretKey>(std::move(*key));
	auto body = Backend::EncodeDefaultWrapRequest(proposed->bytes());
	if (!body) {
		block(Error::InvalidData);
		return;
	}
	http("POST", u"account/wrap-default"_q, std::move(body),
		[=, this](int status, const QByteArray &bytes) {
			const auto result = Backend::ParseOk(status, View(bytes));
			if (result.value && *result.value) {
				if (!acceptMasterKey(std::move(*proposed))) {
					return;
				}
				maximumMode = false;
				pull();
			} else if (status == 409 && result.failure.code == "already_wrapped_or_wrong_mode") {
				fetchKey();
			} else {
				failure(result.failure);
			}
		});
}

void SyncService::Data::pull() {
	if (consentStatus != ConsentStatus::Accepted || awaitingConsent) {
		return;
	}
	if (resetState != ResetState::None) {
		publish(State::Blocked, resetState == ResetState::Confirmed
			? Error::ResetConfirmed : Error::ResetUncertain);
		return;
	}
	if (!masterKey) {
		publish(State::NeedsPassphrase);
		return;
	}
	auto requests = coordinator.pull();
	if (bootstrap && requests.size() == 2) {
		auto snapshot = std::move(*bootstrap);
		bootstrap.reset();
		if (!publish(State::Reading)) {
			return;
		}
		const auto before = epoch;
		const auto guard = QPointer<SyncService>(owner);
		for (const auto &request : requests) {
			acceptBlob(request, request.kind == Sync::BlobKind::Filter
				? std::move(snapshot.filter) : std::move(snapshot.content));
			if (!guard || guard->_data->epoch != before) {
				return;
			}
		}
	} else {
		dispatch(std::move(requests));
	}
}

void SyncService::Data::updateState() {
	switch (coordinator.phase()) {
	case Sync::SyncPhase::Closed: publish(State::Idle); break;
	case Sync::SyncPhase::Reading: publish(State::Reading); break;
	case Sync::SyncPhase::Writing: publish(State::Writing); break;
	case Sync::SyncPhase::Ready:
		transportRetries = 0;
		if (metadataStatus == MetadataStatus::Ready) {
			renewalRetried = false;
		}
		poll.start();
		publish(State::Ready);
		break;
	case Sync::SyncPhase::Blocked:
		switch (coordinator.failure()) {
		case Sync::SyncFailure::UnsupportedSchema: publish(State::Blocked, Error::UnsupportedSchema); break;
		case Sync::SyncFailure::ConflictLimit: publish(State::Blocked, Error::ConflictLimit); break;
		case Sync::SyncFailure::AuthorizationChanged: publish(State::Blocked, Error::AuthorizationChanged); break;
		case Sync::SyncFailure::Transport: publish(State::Blocked, Error::Transport); break;
		default: publish(State::Blocked, Error::InvalidData); break;
		}
		break;
	}
}

void SyncService::Data::dispatch(std::vector<Sync::SyncRequest> requests) {
	const auto before = epoch;
	const auto guard = QPointer<SyncService>(owner);
	updateState();
	if (!guard || epoch != before) {
		return;
	}
	for (const auto &request : requests) {
		const auto path = request.kind == Sync::BlobKind::Filter ? u"filter"_q : u"content"_q;
		if (request.operation == Sync::SyncOperation::Read) {
			http("GET", path, std::nullopt,
				[=, this](int status, const QByteArray &bytes) {
					auto result = Backend::ParseBlob(status, View(bytes));
					if (!result.value) {
						failure(result.failure);
					} else {
						acceptBlob(request, std::move(*result.value));
					}
				});
		} else {
			prepareWrite(request);
		}
		if (!guard || guard->_data->epoch != before) {
			return;
		}
	}
}

void SyncService::Data::prepareWrite(Sync::SyncRequest request) {
	if (maximumMode && !canUnlockMaximum()) {
		owner->lockMax();
		return;
	}
	http("GET", u"account/key"_q, std::nullopt,
		[=, this](int status, const QByteArray &bytes) {
			auto result = Backend::ParseAccountKey(status, View(bytes));
			if (!result.value) {
				failure(result.failure);
				return;
			}
			if (auto key = std::get_if<Backend::DefaultKey>(&*result.value)) {
				if (!maximumMode) {
					if (acceptMasterKey(std::move(key->masterKey))) {
						sendWrite(request);
					}
					return;
				}
			} else if (const auto key = std::get_if<Backend::MaximumPrivacyKey>(
					&*result.value)) {
				if (maximumMode && maximumKey && SameMaximumKey(*key, *maximumKey)) {
					if (!canUnlockMaximum()) {
						owner->lockMax();
					} else {
						sendWrite(request);
					}
					return;
				}
			} else {
				block(Error::GenerationChanged);
				return;
			}
			cancel();
			keepPendingAndClose();
			masterKey.reset();
			bootstrap.reset();
			acceptKey(std::move(*result.value));
		});
}

void SyncService::Data::sendWrite(const Sync::SyncRequest &request) {
	if (!masterKey || !request.plaintext) {
		block(Error::InvalidData);
		return;
	}
	const auto &text = *request.plaintext;
	auto sealed = Sync::SealBlob(
		{ reinterpret_cast<const unsigned char*>(text.data()), text.size() },
		masterKey->bytes());
	auto body = sealed
		? Backend::EncodePutRequest(*sealed, request.previousVersion)
		: std::nullopt;
	if (!body) {
		block(Error::InvalidData);
		return;
	}
	const auto path = request.kind == Sync::BlobKind::Filter ? u"filter"_q : u"content"_q;
	http("PUT", path, std::move(body),
		[=, this](int status, const QByteArray &bytes) {
			const auto result = Backend::ParsePut(status, View(bytes));
			if (result.value) {
				dispatch(coordinator.acceptWrite(request.id,
					Sync::RemoteWriteStatus::Accepted, result.value->version));
			} else if (result.failure.kind == Backend::FailureKind::VersionConflict) {
				dispatch(coordinator.acceptWrite(request.id, Sync::RemoteWriteStatus::Conflict));
			} else {
				failure(result.failure);
			}
		});
}

void SyncService::Data::acceptBlob(const Sync::SyncRequest &request, Backend::RemoteBlob blob) {
	auto read = Sync::RemoteRead();
	if (std::holds_alternative<Backend::AbsentBlob>(blob)) {
		read.status = Sync::RemoteReadStatus::Absent;
	} else if (masterKey) {
		const auto &remote = std::get<Backend::VersionedBlob>(blob);
		const auto plaintext = Sync::OpenBlob(remote.encrypted.ciphertext,
			remote.encrypted.nonce, masterKey->bytes());
		if (!plaintext) {
			block(Error::InvalidData);
			return;
		}
		read.status = Sync::RemoteReadStatus::Present;
		read.version = remote.version;
		read.plaintext = std::string(View(*plaintext));
	} else {
		block(Error::Authorization);
		return;
	}
	dispatch(coordinator.acceptRead(request.id, std::move(read)));
}

QByteArray SyncService::Data::serialize() const {
	if (!generation) {
		return {};
	}
	const auto result = Sync::EncodeSessionSnapshot(Sync::SessionSnapshot{
		session->userId().bare, *generation, maximumMode, masterFingerprint,
		resetState, coordinator.checkpoint() });
	return result ? QByteArray(result->data(), result->size()) : QByteArray();
}

bool SyncService::Data::restore(const QByteArray &serialized) {
	if (enabled || state != State::Idle) {
		return false;
	} else if (serialized.isEmpty()) {
		return !generation;
	}
	auto snapshot = Sync::ReadSessionSnapshot(View(serialized), session->userId().bare);
	if (!snapshot) {
		return false;
	}
	coordinator.restoreCheckpoint(std::move(snapshot->checkpoint));
	generation = std::move(snapshot->generation);
	masterFingerprint = std::move(snapshot->keyFingerprint);
	resetState = snapshot->reset;
	maximumMode = snapshot->maximum;
	return true;
}

SyncService::SyncService(not_null<Main::Session*> session)
: _data(std::make_unique<Data>(this, session)) {
	_data->watch();
}

SyncService::~SyncService() {
	_data->cancel();
}

void SyncService::start() {
	if (_data->resetState != ResetState::None) {
		if (!_data->resetDone) {
			_data->enabled = true;
			_data->publish(State::Blocked, _data->resetState == ResetState::Confirmed
				? Error::ResetConfirmed : Error::ResetUncertain);
		}
		return;
	}
	if (_data->state == State::Authorizing || _data->state == State::FetchingKey
		|| _data->state == State::Reading || _data->state == State::Writing) {
		return;
	}
	_data->cancel();
	_data->keepPendingAndClose();
	_data->token.clear();
	_data->masterKey.reset();
	_data->bootstrap.reset();
	_data->consentStatus = ConsentStatus::Unknown;
	_data->awaitingConsent = true;
	_data->enabled = true;
	_data->authRetried = _data->renewalRetried = _data->wrapAttempted = false;
	_data->transportRetries = 0;
	_data->authorize();
}

void SyncService::refresh() {
	if (_data->enabled && _data->awaitingConsent && !_data->token.bytes().empty()
		&& _data->state == State::NeedsConsent) {
		_data->fetchMe();
		return;
	}
	if (!_data->enabled || !_data->masterKey || _data->token.bytes().empty()
		|| _data->resetState != ResetState::None
		|| _data->privacyOperation != PrivacyOperation::Idle
		|| _data->error == Error::GenerationChanged
		|| _data->error == Error::AuthorizationChanged
		|| _data->state == State::AccountDeleted
		|| (_data->state != State::Ready && _data->state != State::Blocked)) {
		return;
	}
	if (!_data->fetchMe()) {
		return;
	}
	_data->pull();
}

void SyncService::stop() {
	_data->cancel();
	_data->enabled = false;
	_data->keepPendingAndClose();
	_data->token.clear();
	_data->masterKey.reset();
	_data->maximumKey.reset();
	_data->bootstrap.reset();
	_data->premiumTimer.stop();
	_data->premiumClock.clear();
	_data->metadata.reset();
	_data->metadataReceivedAt.reset();
	_data->metadataStatus = MetadataStatus::Unknown;
	_data->consentStatus = ConsentStatus::Unknown;
	_data->awaitingConsent = false;
	_data->publish(State::Idle);
}

void SyncService::lockMax() {
	if (_data->resetDone) {
		_data->finishReset(false, Error::ResetUncertain);
		return;
	}
	if (_data->consentDone) {
		_data->cancel();
		_data->keepPendingAndClose();
		_data->masterKey.reset();
		_data->bootstrap.reset();
		_data->consentStatus = ConsentStatus::Unknown;
		_data->awaitingConsent = true;
		_data->publish(State::NeedsConsent);
		return;
	}
	if (_data->privacyOperation != PrivacyOperation::Idle) {
		const auto committing = _data->privacyIsCommitting();
		_data->maximumMode = _data->maximumMode
			|| (committing && _data->privacyIsMaximum());
		_data->cancel();
		if (committing || _data->maximumMode) {
			_data->keepPendingAndClose();
			_data->masterKey.reset();
			_data->bootstrap.reset();
			_data->publish(committing ? State::Blocked : State::NeedsPassphrase,
				committing ? Error::Transport : Error::None);
		} else {
			_data->poll.start();
			_data->publish(_data->state, _data->error);
		}
		return;
	}
	if (!_data->maximumMode || !_data->enabled
		|| _data->state == State::NeedsPassphrase || _data->state == State::AccountDeleted) {
		return;
	}
	_data->cancel();
	_data->keepPendingAndClose();
	_data->masterKey.reset();
	_data->bootstrap.reset();
	_data->publish(_data->maximumKey ? State::NeedsPassphrase : State::Idle);
}

void SyncService::unlockMax(const QString &passphrase, bool recovery) {
	if (!_data->canUnlockMaximum()
		|| _data->consentStatus != ConsentStatus::Accepted || _data->awaitingConsent
		|| _data->resetState != ResetState::None
		|| _data->state != State::NeedsPassphrase || !_data->maximumKey) {
		return;
	}
	if (std::size_t(passphrase.size()) > Sync::kMaxSecretBytes) {
		_data->publish(State::NeedsPassphrase, Error::InvalidPassphrase);
		return;
	}
	auto bytes = recovery ? RecoveryBytes(passphrase) : passphrase.toUtf8();
	if (bytes.isEmpty() || std::size_t(bytes.size()) > Sync::kMaxSecretBytes) {
		Wipe(bytes);
		_data->publish(State::NeedsPassphrase, Error::InvalidPassphrase);
		return;
	}
	auto secret = std::make_shared<Sync::SecretBytes>(std::size_t(bytes.size()));
	std::copy(bytes.begin(), bytes.end(), secret->bytes().begin());
	Wipe(bytes);
	_data->unlockMaximum(std::move(secret), recovery);
}

bool SyncService::prepareMaximum(
		const QString &passphrase,
		Fn<void(std::optional<MaximumPreparation>)> done) {
	return done && _data->preparePrivacy(passphrase, std::move(done), nullptr);
}

bool SyncService::acceptTerms(const QString &locale, Fn<void(bool)> done) {
	return _data->acceptTerms(locale, std::move(done));
}

SyncService::ConsentStatus SyncService::consentStatus() const {
	return _data->consentStatus;
}

bool SyncService::needsTermsConsent() const {
	return _data->consentStatus == ConsentStatus::Required;
}

bool SyncService::acceptingTerms() const {
	return bool(_data->consentDone);
}

bool SyncService::commitMaximum(
		std::uint64_t id,
		bool recoverySaved,
		Fn<void(bool)> done) {
	return recoverySaved && _data->commitPrivacy(id, true, std::move(done));
}

bool SyncService::preparePassphraseChange(
		const QString &passphrase,
		Fn<void(std::optional<std::uint64_t>)> done) {
	return done && _data->preparePrivacy(passphrase, nullptr, std::move(done));
}

bool SyncService::commitPassphraseChange(std::uint64_t id, Fn<void(bool)> done) {
	return _data->commitPrivacy(id, false, std::move(done));
}

bool SyncService::downgradePrivacy(bool serverKeyStorageAccepted, Fn<void(bool)> done) {
	return serverKeyStorageAccepted && _data->downgradePrivacy(std::move(done));
}

bool SyncService::resetPrivateSpace(const QString &confirmation, Fn<void(bool)> done) {
	return confirmation == u"RESET"_q && _data->beginReset(std::move(done));
}

bool SyncService::completeLocalReset() {
	if (_data->resetState != ResetState::Confirmed) {
		return false;
	}
	_data->cancel();
	_data->coordinator.close();
	_data->masterKey.reset();
	_data->masterFingerprint.reset();
	_data->maximumKey.reset();
	_data->bootstrap.reset();
	_data->token.clear();
	_data->maximumMode = false;
	_data->resetState = ResetState::None;
	_data->metadata.reset();
	_data->metadataReceivedAt.reset();
	_data->metadataStatus = MetadataStatus::Unknown;
	_data->consentStatus = ConsentStatus::Unknown;
	_data->awaitingConsent = false;
	_data->premiumTimer.stop();
	_data->premiumClock.clear();
	if (_data->publish(State::Idle)) {
		start();
	}
	return true;
}

SyncService::ResetState SyncService::resetState() const {
	return _data->resetState;
}

void SyncService::cancelPrivacyPreparation(std::uint64_t id) {
	if (_data->privacyOperation == PrivacyOperation::Idle
		|| (id && id != _data->privacyId)) {
		return;
	}
	const auto committing = _data->privacyIsCommitting();
	_data->maximumMode = _data->maximumMode
		|| (committing && _data->privacyIsMaximum());
	_data->cancel();
	if (committing) {
		_data->keepPendingAndClose();
		_data->masterKey.reset();
		_data->bootstrap.reset();
		_data->publish(State::Blocked, Error::Transport);
	} else {
		_data->poll.start();
		_data->publish(_data->state, _data->error);
	}
}

bool SyncService::privacyOperationBusy() const {
	return _data->privacyOperation != PrivacyOperation::Idle;
}

bool SyncService::submit(Sync::FilterBlob filter, Sync::ContentBlob content) {
	if (_data->state != State::Ready || !_data->masterKey
		|| _data->consentStatus != ConsentStatus::Accepted || _data->awaitingConsent
		|| _data->resetState != ResetState::None
		|| _data->privacyOperation != PrivacyOperation::Idle) {
		return false;
	}
	auto requests = _data->coordinator.submit(std::move(filter), std::move(content));
	if (requests.empty()) {
		return false;
	}
	_data->dispatch(std::move(requests));
	return true;
}

void SyncService::discardPendingMutation() {
	_data->cancel();
	_data->coordinator.discardPendingMutation();
	_data->publish(State::Blocked);
}

SyncService::State SyncService::state() const {
	return _data->state;
}

SyncService::Error SyncService::error() const {
	return _data->error;
}

bool SyncService::linked() const {
	return _data->generation.has_value();
}

bool SyncService::maxMode() const {
	return _data->maximumMode;
}

SyncService::MetadataStatus SyncService::metadataStatus() const {
	return _data->metadataStatus;
}

const Sync::Backend::MeReply *SyncService::me() const {
	return _data->metadata ? &*_data->metadata : nullptr;
}

std::optional<std::int64_t> SyncService::metadataReceivedAt() const {
	return _data->metadataReceivedAt;
}

Security::PremiumSnapshot SyncService::premium() const {
	return _data->premiumClock.snapshot(MonotonicNow());
}

const Sync::SyncPair *SyncService::projection() const {
	return (_data->state == State::Ready && _data->resetState == ResetState::None
		&& _data->consentStatus == ConsentStatus::Accepted && !_data->awaitingConsent)
		? _data->coordinator.projection() : nullptr;
}

const Sync::SyncPair *SyncService::pendingMutation() const {
	return _data->coordinator.pendingMutation();
}

rpl::producer<> SyncService::changes() const {
	return _data->changes.events();
}

QByteArray SyncService::serialize() const {
	return _data->serialize();
}

bool SyncService::restore(const QByteArray &serialized) {
	return _data->restore(serialized);
}

} // namespace Leemen
