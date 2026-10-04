# Leemen for Windows

Leemen for Windows is a fork of [Telegram Desktop][telegram_desktop], using the [Telegram API][telegram_api] and [MTProto][telegram_proto]. This repository contains source code and build instructions; it is not an official Telegram client.

[![Windows build](https://github.com/leemen-dev/Leemen-Windows/actions/workflows/win.yml/badge.svg)](https://github.com/leemen-dev/Leemen-Windows/actions/workflows/win.yml)
[![Portable core tests](https://github.com/leemen-dev/Leemen-Windows/actions/workflows/leemen-core-tests.yml/badge.svg)](https://github.com/leemen-dev/Leemen-Windows/actions/workflows/leemen-core-tests.yml)

The Windows preview ports Leemen’s Private Space to Telegram Desktop. It includes:

- PIN-protected hidden chats and accounts, automatic locking when the app loses focus, and optional account-switch PINs.
- Encrypted Android-compatible synchronization, realtime updates, maximum privacy with a passphrase and recovery words.
- Explicit message visibility outside Private Space, private drafts, filtered notifications, search, Stories, Saved Messages and downloads.
- Leemen account status, promo codes, subscription limits, consent, explicit reset and account deletion.
- A tested keyboard shortcut, screenshot protection and Telegram session / two-step-verification checks.

Open **Settings → Privacy and Security → Leemen Private Space** or press **Ctrl+Shift+L** in a preview build. Leemen uses its own Windows application identity and data directory. Downloaded or exported files remain accessible outside the app.

## Build and verification

See the [Android parity matrix](docs/leemen-parity.md) and [Windows Debug build instructions](docs/building-win.md#leemen-private-space-preview). Manual source builds require `TDESKTOP_ENABLE_LEEMEN_PRIVATE_SPACE=ON`; this fork’s Windows CI preview enables it. Upstream Telegram auto-updates are disabled.

Portable component tests run on Windows and Linux. The full Windows Qt client is compiled separately without launching it. Passing component tests alone does not verify the full UI or Android↔Windows account behavior; use a disposable test account for preview acceptance.

The backend currently does not accept Windows device registration. Cloud synchronization does not depend on that registration. Windows store billing and telemetry are not enabled; the client can read server entitlements and redeem promo codes.

This repository contains source and CI previews, not a signed production release. The source is published under GPLv3 with the OpenSSL exception; see [LICENSE](LICENSE).

## Third-party

* Qt 6 ([LGPL](http://doc.qt.io/qt-6/lgpl.html)) and Qt 5.15 ([LGPL](http://doc.qt.io/qt-5/lgpl.html)) slightly patched
* OpenSSL 3.2.1 ([Apache License 2.0](https://openssl-library.org/source/license/apache-license-2.0.txt))
* WebRTC ([New BSD License](https://github.com/desktop-app/tg_owt/blob/master/LICENSE))
* zlib ([zlib License](http://www.zlib.net/zlib_license.html))
* LZMA SDK 9.20 ([public domain](http://www.7-zip.org/sdk.html))
* liblzma ([public domain](http://tukaani.org/xz/))
* Google Breakpad ([License](https://chromium.googlesource.com/breakpad/breakpad/+/master/LICENSE))
* Google Crashpad ([Apache License 2.0](https://chromium.googlesource.com/crashpad/crashpad/+/master/LICENSE))
* GYP ([BSD License](https://github.com/bnoordhuis/gyp/blob/master/LICENSE))
* Ninja ([Apache License 2.0](https://github.com/ninja-build/ninja/blob/master/COPYING))
* OpenAL Soft ([LGPL](https://github.com/kcat/openal-soft/blob/master/COPYING))
* Opus codec ([BSD License](http://www.opus-codec.org/license/))
* FFmpeg ([LGPL](https://www.ffmpeg.org/legal.html))
* Guideline Support Library ([MIT License](https://github.com/Microsoft/GSL/blob/master/LICENSE))
* Range-v3 ([Boost License](https://github.com/ericniebler/range-v3/blob/master/LICENSE.txt))
* Open Sans font ([Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0.html))
* Vazirmatn font ([SIL Open Font License 1.1](https://github.com/rastikerdar/vazirmatn/blob/master/OFL.txt))
* Emoji alpha codes ([MIT License](https://github.com/emojione/emojione/blob/master/extras/alpha-codes/LICENSE.md))
* xxHash ([BSD License](https://github.com/Cyan4973/xxHash/blob/dev/LICENSE))
* QR Code generator ([MIT License](https://github.com/nayuki/QR-Code-generator#license))
* CMake ([New BSD License](https://github.com/Kitware/CMake/blob/master/Copyright.txt))
* Hunspell ([LGPL](https://github.com/hunspell/hunspell/blob/master/COPYING.LESSER))
* Ada ([Apache License 2.0](https://github.com/ada-url/ada/blob/main/LICENSE-APACHE))

## Build instructions

* [Windows (32-bit and 64-bit)][win]
* [macOS][mac]
* [GNU/Linux using Docker][linux]

[//]: # (LINKS)
[telegram]: https://telegram.org
[telegram_desktop]: https://desktop.telegram.org
[telegram_api]: https://core.telegram.org
[telegram_proto]: https://core.telegram.org/mtproto
[license]: LICENSE
[win]: docs/building-win.md
[mac]: docs/building-mac.md
[linux]: docs/building-linux.md

## Thanks to

<a href="https://depot.dev">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://depot.dev/assets/brand/1693758816/depot-logo-horizontal-on-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://depot.dev/assets/brand/1693758816/depot-logo-horizontal-on-light.svg">
    <img alt="Depot" src="https://depot.dev/assets/brand/1693758816/depot-logo-horizontal-on-light.svg" width="150">
  </picture>
</a>

CI infrastructure sponsored by [Depot](https://depot.dev) — fast GitHub Actions runners.
