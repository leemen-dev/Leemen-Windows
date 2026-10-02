#pragma once

#include "leemen/realtime_protocol.h"

#include <QtCore/QElapsedTimer>
#include <QtCore/QObject>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtNetwork/QSslSocket>

namespace Leemen {

class SyncRealtime final : public QObject {
public:
	explicit SyncRealtime(Fn<void()> remoteChanged, QObject *parent = nullptr);
	~SyncRealtime();
	[[nodiscard]] bool start(const QString &syncAccountUuid);
	void reconnectNow();
	void stop();

private:
	enum class State { Stopped, Connecting, Upgrade, Joining, Joined, Backoff };
	void connectSocket();
	void encrypted();
	void read();
	bool consume(std::span<const unsigned char> bytes);
	bool writeFrame(Sync::Realtime::Opcode opcode, std::span<const unsigned char> bytes);
	bool writeText(const std::optional<std::string> &text);
	void tick();
	void hint();
	void drop();
	void disposeSocket();
	[[nodiscard]] std::string nextReference();

	const Fn<void()> _remoteChanged;
	QPointer<QSslSocket> _socket;
	QElapsedTimer _clock;
	QTimer _watchdog;
	QTimer _reconnect;
	QTimer _hintTimer;
	Sync::Realtime::Decoder _decoder;
	State _state = State::Stopped;
	std::string _syncId;
	std::string _topic;
	std::string _accept;
	std::string _joinRef;
	std::string _heartbeatRef;
	QByteArray _upgrade;
	std::array<unsigned char, 8> _ping = {};
	std::uint64_t _reference = 0;
	std::uint64_t _connection = 0;
	qint64 _deadline = 0;
	qint64 _heartbeatAt = 0;
	qint64 _heartbeatDeadline = 0;
	qint64 _pingAt = 0;
	qint64 _pongDeadline = 0;
	qint64 _nextHintAt = 0;
	qint64 _budgetAt = 0;
	std::size_t _budgetBytes = 0;
	int _backoff = 0;
	bool _readScheduled = false;

};

} // namespace Leemen
