# Android → Windows parity

Reference: Android Leemen commit `2da0b71bbdf45bba833af19a209e492bfda3c1e5`. Windows builds use the existing Telegram Desktop C++/Qt UI and MTProto session, with Leemen components under `Telegram/SourceFiles/leemen`.

| Android behavior | Windows implementation | Verification |
| --- | --- | --- |
| Private Space entry, exit, PIN and timeout | PrivateSpace adapter; local PBKDF2 migration to synchronized Argon2id; close on focus loss, account switch and app lock | Portable state/PIN/security tests; native acceptance pending |
| Shared hidden-chat membership and settings | Schema-2 codec, merge, canonical peer/message IDs, durable local intent journal and CAS coordinator | Codec/coordinator/snapshot tests, including corrupt and unsupported data |
| Ordinary chats without a network connection | Encrypted local checkpoint retains the last fully confirmed hidden-chat membership; unknown state and unsafe pending operations close access; Private Space still requires fresh synchronization | Coordinator and snapshot restart, identity, key, version and invalidation tests |
| Encrypted sync and maximum privacy | XChaCha20-Poly1305, Android KDF/wrap parameters, recovery words, upgrade/change/downgrade and explicit reset | Crypto/maximum-privacy tests; live cross-device acceptance pending |
| Realtime account/blob hints | Verified TLS WebSocket/Phoenix client; hints only trigger REST verification; polling remains active | Protocol tests; native connection acceptance pending |
| Hidden accounts and separate switch PIN | Local encrypted owner graph; new hidden-account sign-in with persistent slot reservation, resume/cancel and restart reconciliation; selection, notifications, windows and account content gates | Portable graph tests and ASan/UBSan; native multi-account acceptance pending |
| Pending/exposed/hidden messages and own pins | Explicit visibility controls and pending-message decision; bounded outside-space viewer with text sending, own-pin controls and a single permitted photo/video/animation preview | Portable policy tests; native MTProto acceptance pending |
| Private drafts, source-aware filtering and counters | Guards in history, search, Stories, Saved Messages, notifications, unread counts, downloads, calls, export and separate windows | Source review; native acceptance pending |
| Account terms, status and limits | Consent gate, server-time entitlement clock, limit resolution, devices and promo codes | Backend codec and security tests; native account acceptance pending |
| Reset and account deletion | Explicit RESET/DELETE; persistent uncertainty; no automatic repeated destructive request | Backend/snapshot tests; real destructive acceptance pending |
| Entry customization | Test the assigned keyboard shortcut before hiding visible entry; changing it restores visible entry | Source review; native shortcut acceptance pending |
| Telegram privacy warnings | Fresh session and cloud-password checks, links to Telegram settings | Source/API review; native UI acceptance pending |
| Private Space introduction | Four translated steps after opening management, explicit completion stored per local account, replay from settings | Serialization and lifecycle source review; native UI acceptance pending |

## Desktop adaptations

Hidden-account ownership and its switch PIN belong to this local Windows profile. They do not change another device's local account selector. A missing owner, damaged settings, uncertain server result or unsupported cloud schema never makes protected content public automatically.

Outside Private Space, the dedicated message viewer supports permitted text and captions, sending text, own-pin actions and individual photo/video/animation previews. A preview is tied to the exact account, message and media object and closes when access is revoked. It disables gallery navigation, preloading neighboring media, picture-in-picture, external opening, saving and automatic export. Timed/single-view media, other files, quoted-message navigation, the native hidden-chat history, media collections and full-message search open inside Private Space. This is narrower than Android's full filtered chat view.

Calls involving a hidden peer are ended when that peer becomes inaccessible, including when Private Space closes.

PIN protection controls access inside Leemen. Already downloaded/exported files and Telegram's media cache are not converted into a new PIN-encrypted storage format.

Leemen account deletion deletes Leemen service data and signs the local account out after server confirmation. The local hidden-account logout policy also signs its hidden accounts out. It does not delete Telegram accounts or their messages. An uncertain result survives restart and only permits status verification or a newly confirmed attempt.

## External requirements and protocol limits

- The backend currently accepts device-registration platforms `android`, `ios` and `web`, and rejects `windows`. Windows does not impersonate one of them. Blob synchronization uses Telegram-derived authorization and does not depend on device registration.
- Store billing and analytics are not enabled in Windows. Server entitlements and promo redemption are supported.
- A production build requires the application's own Telegram API credentials. CI uses Telegram's limited test credentials and creates a Debug preview, not a signed release.
- The existing backend has no atomic key-epoch precondition on blob PUT. Client preflight checks and version floors cannot eliminate a server-side key-change/write race.

## Acceptance boundary

Portable CTest targets cover pure components and run on Windows/Linux. ASan/UBSan checks run separately where available. They do not instantiate the complete Qt application or prove that every native surface is filtered.

The Windows workflow compiles the entire client without launching `Leemen.exe`. Cross-device synchronization, multi-window privacy, account switching, live media and actual reset/deletion remain manual scenarios for the owner of test accounts; see [the Windows acceptance instructions](building-win.md#verification-status).
