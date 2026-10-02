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
* Select Telegram project and press Build > Build Telegram (Debug and Release configurations)
* The result Telegram.exe will be located in **D:\TBuild\tdesktop\out\Debug** (and **Release**)

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

Enrollment in the experimental local Private Space is disabled by default. For a test-account Debug build, add this option to the configure command:

    configure.bat x64 qt6 -D TDESKTOP_API_ID=YOUR_API_ID -D TDESKTOP_API_HASH=YOUR_API_HASH -D TDESKTOP_ENABLE_LEEMEN_PRIVATE_SPACE=ON
    cmake --build ..\out --config Debug --target Telegram

Run the Debug executable with a separate test profile, for example `Telegram.exe -workdir D:\LeemenTestData`, after creating that empty directory. Upstream Telegram auto-updates are disabled in this fork so they cannot replace its privacy guards.

Open **Settings → Privacy and Security → Leemen Private Space**, create a local PIN, then open the same item again to enter. While inside Private Space, right-click a chat and choose **Hide in Private Space**. Use **Lock Private Space** in the main menu to exit. Leaving the application or switching accounts also locks it. The private-space settings allow changing the PIN or explicitly revealing all locally hidden chats.

This is a local prototype: the PIN and hidden chat selection do not synchronize with Android. Message exposure, hidden accounts, backend synchronization, subscription handling and remaining privacy surfaces are not release-ready. Use only test data. The CMake flag controls new enrollment; already configured profiles remain protected and accessible even in builds without this flag.

The preview also filters story sources, Saved Messages copied from hidden chats, and the download list and progress bar. Download visibility follows each file's owning account. Restored Saved Messages downloads whose source can no longer be resolved remain hidden until Private Space is opened. Files already saved to disk remain accessible outside Leemen.

Telegram data export requires entering Private Space when it is configured. Locking stops the export; files already written are retained. Verify these paths with a test account after every native build: lock while viewing a story, a Saved Messages album, or downloads; switch accounts during a download; restart with completed downloads; unlock and check that the permitted content returns. These UI paths have not yet passed Windows runtime acceptance.

The **Windows.** GitHub Actions workflow supports a manual run with an optional `leemen_private_space` switch. A manual run builds only x64/Qt6 Debug on a standard hosted Windows runner, using Telegram test API configuration. Fork pull requests also use standard hosted runners. This workflow prepares build artifacts; it does not publish a release. A workflow added on a feature branch becomes available for manual dispatch after it is present on the repository's default branch.

### Portable component tests

These tests require CMake 3.20+, a C++20 compiler and OpenSSL development files. They compile the privacy model, local PIN helper and Android-compatible identifier codec without Qt or the full Telegram dependency tree:

    cmake -S tools/leemen -B out/leemen-core
    cmake --build out/leemen-core --config Debug
    ctest --test-dir out/leemen-core -C Debug --output-on-failure

For vcpkg on Windows, add `-DCMAKE_TOOLCHAIN_FILE=PATH_TO_VCPKG/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows` to configuration after installing `openssl:x64-windows`. The separate **Leemen portable core tests** workflow runs these components on Windows and Linux. Passing these tests does not validate the Qt GUI or establish privacy coverage.
