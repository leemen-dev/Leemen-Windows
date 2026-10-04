# Build instructions for Windows

- [Prepare folder](#prepare-folder)
- [Install third party software](#install-third-party-software)
- [Choose architecture and initialize terminal](#choose-architecture-and-initialize-terminal)
- [Clone source code and prepare libraries](#clone-source-code-and-prepare-libraries)
- [Build the project](#build-the-project)
- [Qt Visual Studio Tools](#qt-visual-studio-tools)

## Prepare folder

The build is done in **Visual Studio 2026** with **10.0.26100.0** SDK version.

Choose an empty folder for the future build, for example **D:\\TBuild**. It will be named ***BuildPath*** in the rest of this document. Create two folders there, ***BuildPath*\\ThirdParty** and ***BuildPath*\\Libraries**.

The default modern toolset from Visual Studio 2026 (`v145`) does not support Windows 7, so for Telegram Desktop you must use `-vcvars_ver=14.44` (`v144.4`, based on `v143` with Windows 7 support).

### Obtain your API credentials

You will require **api_id** and **api_hash** to access the Telegram API servers. To learn how to obtain them [click here][api_credentials].

## Install third party software

* Download **Python 3.10** installer from [https://www.python.org/downloads/](https://www.python.org/downloads/) and install it with adding to PATH.
* Download **Git** installer from [https://git-scm.com/download/win](https://git-scm.com/download/win) and install it.

## Choose architecture and initialize terminal

Before preparing libraries and running build commands, initialize the Visual Studio environment for your target architecture.
The default modern toolset from Visual Studio 2026 (`v145`) does not support Windows 7, so for Telegram Desktop you must use `-vcvars_ver=14.44` (`v144.4`, based on `v143` with Windows 7 support).

For `win` (32-bit):

    %comspec% /k "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat" -vcvars_ver=14.44

For `win64` (64-bit):

    %comspec% /k "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" -vcvars_ver=14.44

Run both `Clone source code and prepare libraries` and `Build the project` sections in the terminal initialized with one of the commands above.

## Clone source code and prepare libraries

In the initialized terminal, go to ***BuildPath*** and run

    git clone --recursive https://github.com/telegramdesktop/tdesktop.git
    tdesktop\Telegram\build\prepare\win.bat

## Build the project

Go to ***BuildPath*\\tdesktop\\Telegram** and run (using [your **api_id** and **api_hash**](#obtain-your-api-credentials)):

For `win` (32-bit):

    configure.bat -D TDESKTOP_API_ID=YOUR_API_ID -D TDESKTOP_API_HASH=YOUR_API_HASH

For `win64` (64-bit):

    configure.bat x64 -D TDESKTOP_API_ID=YOUR_API_ID -D TDESKTOP_API_HASH=YOUR_API_HASH

* Open ***BuildPath*\\tdesktop\\out\\Telegram.slnx** in Visual Studio 2026
* Select Telegram project and press Build > Build Telegram (Debug configuration)
* The result Leemen.exe will be located in **D:\TBuild\tdesktop\out\Debug**

### Qt Visual Studio Tools

For better debugging you may want to install Qt Visual Studio Tools:

* Open **Extensions** -> **Manage Extensions**
* Go to **Online** tab
* Search for **Qt**
* Install **Qt Visual Studio Tools** extension

[api_credentials]: api_credentials.md

## Leemen Private Space preview

Use the Leemen fork when following the source checkout step:

    git clone --recursive https://github.com/leemen-dev/Leemen-Windows.git tdesktop

Enrollment in Private Space is disabled by default. Add the experimental option to a test-account Debug build:

    configure.bat x64 qt6 -D TDESKTOP_API_ID=YOUR_API_ID -D TDESKTOP_API_HASH=YOUR_API_HASH -D TDESKTOP_ENABLE_LEEMEN_PRIVATE_SPACE=ON -D CMAKE_CONFIGURATION_TYPES=Debug
    cmake --build ..\out --config Debug --target Telegram

The build target remains `Telegram`; the Windows executable is `Leemen.exe`. Leemen uses a separate application-data directory, application identity and Windows shortcut. For a disposable test profile, create an empty directory and launch `Leemen.exe -workdir D:\LeemenTestData`. Explicit portable mode uses a `LeemenForcePortable` directory next to the executable. Upstream Telegram auto-updates are disabled.

Open **Settings → Privacy and Security → Leemen Private Space** or press **Ctrl+Shift+L**. Connect the account to Leemen, accept the current Terms and Privacy Policy if needed, and set or enter the synchronized PIN. Existing Android maximum-privacy accounts first require their passphrase or recovery words. While inside Private Space, right-click a chat and choose **Hide in Private Space**. Leaving the application, switching accounts, or explicitly locking closes protected views.

The management screen provides PIN timeout, screenshot protection, maximum privacy and recovery setup, password changes, explicit reset, and hidden-account management. Hiding the entry button requires first testing the assigned shortcut. The free allowance is one hidden chat and no hidden accounts; an expired subscription with a larger hidden set offers renewal information or explicit reveal after PIN verification. Expiry never reveals data automatically. Hidden-account relationships and their optional switch PIN are local to this Windows profile.

The **Leemen account** screen shows current server subscription status and linked devices, accepts promo codes and provides an explicit account-deletion flow. Deletion requires typing `DELETE` for every attempt. A lost server response leaves a durable quarantine; restarting checks the existing account generation and never repeats deletion automatically. Confirmed deletion signs the account and accounts hidden by it out of this Windows profile. Telegram accounts and messages are not deleted.

The **Privacy check** screen checks Telegram two-step verification and sessions opened by other API clients, with links to Telegram’s existing settings. A failed request is shown as unavailable, not as a successful security check.

Synchronization uses the Android schema-2 filter/content blobs, XChaCha20-Poly1305 encryption and Argon2id PIN/key wrappers. Local unconfirmed mutations, exact authorization stamps, version floors and reset quarantine survive restart in encrypted Telegram session storage. A reset whose server result is unknown remains locked; another destructive request requires typing `RESET` again. The current backend cannot atomically bind blob writes to a key epoch, so a server-side key-change/write race remains a protocol limitation.

The OFF message viewer displays only explicitly permitted text and captions, and can send text. Native hidden-chat history, media galleries and full-message search require entering Private Space. Story sources, copied Saved Messages provenance, download lists, unread counters, notifications, export and separate windows are filtered. Files already downloaded or exported remain accessible outside Leemen; this feature does not encrypt or erase the entire Telegram media cache.

### Verification status

Portable component tests run on Windows and Linux. The complete Qt client is being checked separately with the Windows Debug workflow; source integration and passing component tests do not establish GUI runtime acceptance. Use a disposable test account until the native acceptance scenarios below have been checked.

Test normal and maximum privacy across Android and Windows; restart with a pending mutation or uncertain reset; change PIN on another device; expire the subscription; and hide or switch an account with several windows open. Lock while viewing Stories, Saved Messages albums, downloads, export, a reply preview, pending-message review or recovery words. Verify that notifications and badges remain hidden, that discarded callbacks cannot reopen content, and that permitted content returns after an authorized unlock.

Save separate chat, topic, Saved Messages and shared-media windows, then restart outside Private Space. A hidden source must not expose a saved title or a restoration shell. Leave transfers running in hidden chats, close Private Space and quit: hidden transfers must not open a confirmation dialog. Lock after opening a visible transfer confirmation and verify that **Show file** cannot reopen inaccessible content.

Add a new account from **Hidden accounts**, interrupt sign-in and restart the profile. Confirm that its slot remains hidden and that only its owner can continue or cancel sign-in. Repeat with a duplicate account, focus loss, app passcode lock and cancellation while an authorization response is arriving. After successful cloud synchronization, restart without a network connection: ordinary chats should remain usable, known hidden chats stay closed, and Private Space waits for fresh synchronization. A profile without a confirmed cloud checkpoint should keep non-service chats closed until synchronization succeeds.

The backend currently rejects `platform: windows` device registration. Blob synchronization does not require device registration; the client does not pretend to be an Android or web device. Windows store billing and telemetry are not enabled. Leemen Premium can be renewed in Android and its server entitlement refreshed in Windows.

The **Windows.** GitHub Actions workflow runs manually for this fork and builds x64/Qt6 Debug on a hosted Windows runner with Telegram test API configuration. Fork runs enable the Private Space preview. `prepare_only` populates the dependency cache; ordinary runs compile `Leemen.exe` and upload the executable without launching the client. They do not publish a release. Runtime acceptance remains a manual task for the owner of test accounts. Prepared dependencies are saved before compiling the client so a compiler failure does not require rebuilding Qt.

### Portable component tests

These tests require CMake 3.20+, a C++20 compiler and OpenSSL development files. The pinned libsodium dependency is prepared by CMake. The targets cover the privacy state, local PIN, identifiers, schema/merge rules, encryption, backend codec, sync coordinator and durable checkpoint, subscription deadlines, maximum privacy, hidden-account graph, message visibility, realtime protocol and durable reset/deletion quarantine:

    cmake -S tools/leemen -B out/leemen-core -DCMAKE_BUILD_TYPE=Debug
    cmake --build out/leemen-core --config Debug
    ctest --test-dir out/leemen-core -C Debug --output-on-failure

For vcpkg on Windows, add `-DCMAKE_TOOLCHAIN_FILE=PATH_TO_VCPKG/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows` to configuration after installing `openssl:x64-windows`. For an offline libsodium archive, set `LEEMEN_SODIUM_ARCHIVE` to the verified 1.0.22 source archive. The **Leemen portable core tests** workflow runs these components on Windows and Linux.
