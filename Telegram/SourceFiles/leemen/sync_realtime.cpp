#include "leemen/sync_realtime.h"

#include <openssl/rand.h>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslError>
#include <algorithm>
#include <limits>

namespace Leemen {
namespace {

using namespace Sync::Realtime;
constexpr auto kHost = "voyoecrgmtdtplazsvih.supabase.co";
// Public Android production anon key; the subscription grants no REST authority.
constexpr auto kPublicKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZveW9lY3JnbXRkdHBsYXpzdmloIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkwMDM1NzQsImV4cCI6MjA5NDU3OTU3NH0.Y_L1FO1EaLUo9T6UNkY_C-2EkqnSg37yLDQ0TplkAHA";

std::span<const unsigned char> Bytes(const QByteArray &value) {
	return { reinterpret_cast<const unsigned char*>(value.constData()), std::size_t(value.size()) };
}

std::span<const unsigned char> Bytes(const std::string &value) {
	return { reinterpret_cast<const unsigned char*>(value.data()), value.size() };
}

} // namespace

SyncRealtime::SyncRealtime(Fn<void()> remoteChanged, QObject *parent)
: QObject(parent)
, _remoteChanged(std::move(remoteChanged)) {
	_clock.start();
	_watchdog.setInterval(1000);
	_reconnect.setSingleShot(true);
	_hintTimer.setSingleShot(true);
	connect(&_watchdog, &QTimer::timeout, this, [=] { tick(); });
	connect(&_reconnect, &QTimer::timeout, this, [=] {
		if (_state == State::Backoff) connectSocket();
	});
	connect(&_hintTimer, &QTimer::timeout, this, [=] {
		if (_state != State::Joined) return;
		_nextHintAt = _clock.elapsed() + 2000;
		const auto callback = _remoteChanged;
		if (callback) callback();
	});
}

SyncRealtime::~SyncRealtime() {
	stop();
}

bool SyncRealtime::start(const QString &syncAccountUuid) {
	if (syncAccountUuid.size() != 36) { stop(); return false; }
	const auto bytes = syncAccountUuid.toLatin1();
	const auto id = std::string(bytes.constData(), std::size_t(bytes.size()));
	const auto topic = Topic(id);
	if (!topic) { stop(); return false; }
	if (_state != State::Stopped && id == _syncId) return true;
	stop();
	_syncId = id;
	_topic = *topic;
	connectSocket();
	return true;
}

void SyncRealtime::reconnectNow() {
	if (_state != State::Backoff) return;
	_reconnect.stop();
	_backoff = 0;
	connectSocket();
}

void SyncRealtime::stop() {
	if (_state == State::Joined && _socket) {
		constexpr auto normal = std::array<unsigned char, 2>{ 3, 232 };
		if (writeFrame(Opcode::Close, normal) && _socket) _socket->flush();
	}
	_state = State::Stopped;
	_watchdog.stop();
	_reconnect.stop();
	_hintTimer.stop();
	disposeSocket();
	_syncId.clear();
	_topic.clear();
	_backoff = 0;
	_nextHintAt = 0;
}

void SyncRealtime::disposeSocket() {
	++_connection;
	const auto socket = _socket.data();
	_socket.clear();
	if (socket) {
		QObject::disconnect(socket, nullptr, this, nullptr);
		socket->abort();
		socket->deleteLater();
	}
	_decoder.clear();
	_upgrade.clear();
	_accept.clear();
	_joinRef.clear();
	_heartbeatRef.clear();
	_deadline = _heartbeatDeadline = _pongDeadline = 0;
	_readScheduled = false;
}

void SyncRealtime::connectSocket() {
	if (_syncId.empty()) return;
	disposeSocket();
	_state = State::Connecting;
	_deadline = _clock.elapsed() + 15000;
	_budgetAt = _clock.elapsed();
	_budgetBytes = 0;
	const auto socket = new QSslSocket(this);
	_socket = socket;
	socket->setReadBufferSize(qint64(kMaxFeedBytes));
	auto configuration = QSslConfiguration::defaultConfiguration();
	configuration.setProtocol(QSsl::TlsV1_2OrLater);
	configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);
	configuration.setAllowedNextProtocols({ QByteArray("http/1.1") });
	socket->setSslConfiguration(configuration);
	socket->setPeerVerifyName(QString::fromLatin1(kHost));
	connect(socket, &QSslSocket::encrypted, this, [=] {
		if (_socket == socket) encrypted();
	});
	connect(socket, &QSslSocket::readyRead, this, [=] {
		if (_socket == socket) read();
	});
	connect(socket, &QSslSocket::disconnected, this, [=] {
		if (_socket == socket) drop();
	});
	connect(socket, &QAbstractSocket::errorOccurred, this, [=](QAbstractSocket::SocketError) {
		if (_socket == socket) drop();
	});
	connect(socket, &QSslSocket::sslErrors, this, [=](const QList<QSslError> &) {
		if (_socket == socket) drop();
	});
	_watchdog.start();
	socket->connectToHostEncrypted(QString::fromLatin1(kHost), 443);
}

void SyncRealtime::encrypted() {
	if (_state != State::Connecting || !_socket || !_socket->isEncrypted()) return;
	auto nonce = std::array<unsigned char, 16>();
	if (RAND_bytes(nonce.data(), int(nonce.size())) != 1) { drop(); return; }
	const auto key = QByteArray(reinterpret_cast<const char*>(nonce.data()), int(nonce.size())).toBase64();
	const auto accept = UpgradeAccept(std::string_view(key.constData(), std::size_t(key.size())));
	if (!accept) { drop(); return; }
	_accept = *accept;
	const auto request = QByteArray("GET /realtime/v1/websocket?apikey=") + kPublicKey
		+ "&vsn=1.0.0 HTTP/1.1\r\nHost: " + kHost
		+ "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "
		+ key + "\r\n\r\n";
	_state = State::Upgrade;
	_deadline = _clock.elapsed() + 15000;
	if (_socket->write(request) != request.size()) drop();
}

std::string SyncRealtime::nextReference() {
	return _reference == std::numeric_limits<std::uint64_t>::max()
		? std::string() : std::to_string(++_reference);
}

bool SyncRealtime::writeFrame(Opcode opcode, std::span<const unsigned char> bytes) {
	if (!_socket || !_socket->isEncrypted() || _socket->bytesToWrite() > 32 * 1024) return false;
	const auto socket = _socket.data();
	const auto before = _connection;
	auto mask = std::array<unsigned char, 4>();
	if (RAND_bytes(mask.data(), int(mask.size())) != 1) return false;
	const auto frame = ClientFrame(opcode, bytes, mask);
	return frame && socket->write(reinterpret_cast<const char*>(frame->data()), qint64(frame->size())) == qint64(frame->size())
		&& _socket == socket && _connection == before;
}

bool SyncRealtime::writeText(const std::optional<std::string> &text) {
	return text && writeFrame(Opcode::Text, Bytes(*text));
}

void SyncRealtime::read() {
	if (!_socket || (_state != State::Upgrade && _state != State::Joining && _state != State::Joined)) return;
	const auto socket = _socket.data();
	const auto connection = _connection;
	for (auto batch = 0; batch != 4 && socket->bytesAvailable() > 0; ++batch) {
		const auto input = socket->read(16 * 1024);
		if (_socket != socket || _connection != connection) return;
		if (input.isEmpty()) break;
		const auto now = _clock.elapsed();
		if (now - _budgetAt >= 5000) { _budgetAt = now; _budgetBytes = 0; }
		_budgetBytes += std::size_t(input.size());
		if (_budgetBytes > 256 * 1024) { drop(); return; }
		if (_state == State::Upgrade) {
			_upgrade += input;
			const auto end = _upgrade.indexOf("\r\n\r\n");
			if (end < 0) {
				if (std::size_t(_upgrade.size()) > kMaxUpgradeBytes) { drop(); return; }
				continue;
			}
			if (!ValidUpgrade(std::string_view(_upgrade.constData(), std::size_t(end + 4)), _accept)) { drop(); return; }
			const auto remaining = _upgrade.mid(end + 4);
			_upgrade.clear();
			_state = State::Joining;
			_deadline = now + 15000;
			_joinRef = nextReference();
			if (!writeText(Join(_syncId, kPublicKey, _joinRef)) || !consume(Bytes(remaining))) { drop(); return; }
		} else if (!consume(Bytes(input))) { drop(); return; }
		if (_socket != socket) return;
	}
	if (socket->bytesAvailable() > 0 && !_readScheduled) {
		_readScheduled = true;
		const auto before = _connection;
		QTimer::singleShot(0, this, [=] {
			if (_socket != socket || _connection != before) return;
			_readScheduled = false;
			read();
		});
	}
}

bool SyncRealtime::consume(std::span<const unsigned char> bytes) {
	const auto frames = _decoder.feed(bytes);
	if (!frames) return false;
	for (const auto &frame : *frames) {
		if (frame.opcode == Opcode::Close) {
			if (writeFrame(Opcode::Close, frame.payload) && _socket) _socket->flush();
			return false;
		} else if (frame.opcode == Opcode::Ping) {
			if (!writeFrame(Opcode::Pong, frame.payload)) return false;
		} else if (frame.opcode == Opcode::Pong) {
			if (_pongDeadline && std::ranges::equal(frame.payload, _ping)) _pongDeadline = 0;
		} else {
			const auto text = std::string_view(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size());
			switch (Classify(text, _topic, _joinRef, _heartbeatRef, _state == State::Joined)) {
			case Event::Malformed:
			case Event::ChannelClosed: return false;
			case Event::Joined:
				_state = State::Joined;
				_deadline = 0;
				_backoff = 0;
				_heartbeatAt = _clock.elapsed() + 25000;
				_pingAt = _clock.elapsed() + 20000;
				hint();
				break;
			case Event::HeartbeatAck:
				_heartbeatRef.clear();
				_heartbeatDeadline = 0;
				break;
			case Event::Changed: hint(); break;
			case Event::Ignore: break;
			}
		}
	}
	return true;
}

void SyncRealtime::hint() {
	if (_state != State::Joined || _hintTimer.isActive()) return;
	_hintTimer.start(int(std::max(qint64(0), _nextHintAt - _clock.elapsed())));
}

void SyncRealtime::tick() {
	const auto now = _clock.elapsed();
	if ((_deadline && now >= _deadline) || (_heartbeatDeadline && now >= _heartbeatDeadline)
		|| (_pongDeadline && now >= _pongDeadline)) { drop(); return; }
	if (_state != State::Joined) return;
	if (now >= _heartbeatAt) {
		_heartbeatRef = nextReference();
		_heartbeatAt = now + 25000;
		_heartbeatDeadline = now + 15000;
		if (!writeText(Heartbeat(_heartbeatRef))) { drop(); return; }
	}
	if (now >= _pingAt) {
		_pingAt = now + 20000;
		_pongDeadline = now + 10000;
		if (RAND_bytes(_ping.data(), int(_ping.size())) != 1 || !writeFrame(Opcode::Ping, _ping)) drop();
	}
}

void SyncRealtime::drop() {
	if (_state == State::Stopped || _state == State::Backoff) return;
	_state = State::Backoff;
	_watchdog.stop();
	_hintTimer.stop();
	disposeSocket();
	_backoff = _backoff ? std::min(_backoff * 2, 10000) : 2000;
	auto random = std::array<unsigned char, 2>();
	const auto jitter = RAND_bytes(random.data(), int(random.size())) == 1
		? ((unsigned(random[0]) << 8) | random[1]) % 501 : 0;
	_reconnect.start(_backoff + int(jitter));
}

} // namespace Leemen
