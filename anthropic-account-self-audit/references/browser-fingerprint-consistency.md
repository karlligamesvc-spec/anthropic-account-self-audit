# Browser Fingerprint Consistency

Use this reference when the task mentions GeoTime-Spoofer, GeoMirror, browser spoofing, timezone/locale/geolocation/language consistency, VPN consistency, Chrome extensions, or environment fingerprint risk.

## GeoTime-Spoofer Signals

Repository inspected: https://github.com/Mohammad-Aali/GeoTime-Spoofer at commit `0a66a495068e3fa781222005a693aa2df5b5c671`.

The extension is a Manifest V3 Chrome extension named `GeoTime Spoofer`. Its manifest requests:

- `debugger`
- `storage`
- `activeTab`
- `webNavigation`

Its background script uses Chrome DevTools Protocol through `chrome.debugger` and sends:

- `Emulation.setTimezoneOverride`
- `Emulation.setLocaleOverride`
- `Emulation.setGeolocationOverride`
- `Network.setUserAgentOverride`

It stores profile state in `chrome.storage.local` keys including `targetTimezone` and `isActive`.

## GeoMirror Signals

Repository inspected: https://github.com/Azurboy/geomirror at commit `c7ebfc3d075e211a3af024469fde345ec2add0f6`.

GeoMirror is also a Manifest V3 Chrome extension, but unlike GeoTime-Spoofer it does not rely on `chrome.debugger`. Its manifest requests:

- `storage`
- `alarms`
- `declarativeNetRequest`
- host permissions for IP geolocation, IP info, Overpass, and reverse-geocoding providers such as `ipinfo.io`, `ipwho.is`, `ipapi.co`, `reallyfreegeoip.org`, `overpass-api.de`, and `api.bigdatacloud.net`.

Its content scripts run at `document_start` in both worlds:

- MAIN world scripts patch page-visible APIs such as `navigator.geolocation`, `navigator.permissions.query`, `Date.prototype.getTimezoneOffset`, `Intl.DateTimeFormat`, `Intl.NumberFormat`, `Intl.Collator`, `navigator.language`, and `navigator.languages`.
- Isolated world bridge scripts read `chrome.storage.local` and publish an override payload to the DOM.
- The background service worker uses `chrome.declarativeNetRequest` to set outgoing `Accept-Language`.

GeoMirror-style storage and code hints include `tzEnabled`, `langEnabled`, `fontEnabled`, `acceptLanguage`, `ipTimezone`, `ipLocale`, `overrideLat`, `overrideLon`, `data-geomirror`, and content scripts that combine MAIN-world `document_start` with regional API patching.

## Detection Interpretation

Treat these as risk signals:

- Chromium extension has `debugger` permission and references timezone, geolocation, locale, language, spoofing, or fingerprinting.
- Extension code contains CDP override calls for timezone, locale, geolocation, or user-agent/Accept-Language.
- Extension storage contains GeoTime-style keys such as `targetTimezone` or `isActive`.
- Chromium extension uses `declarativeNetRequest`, MAIN-world `document_start` content scripts, IP/geolocation provider host permissions, and code that patches browser region APIs.
- Extension storage contains GeoMirror-style keys such as `tzEnabled`, `langEnabled`, `acceptLanguage`, or `ipTimezone`.
- Public IP country, system IANA timezone, and browser Accept-Language region do not line up with the account's expected region.

Do not claim that spoofing is present from one signal alone. Report the evidence and ask the user whether the extension/profile is used for Anthropic account access, testing only, or unrelated browsing.

## Safety Boundary

Do not help configure spoofing to bypass Anthropic regional restrictions, account integrity checks, anti-abuse systems, or bans. Do not present unverified claims such as language-threshold mass bans as established fact. Offer compliant alternatives: separate testing profiles from account access, disable environment spoofing while using Claude Code, keep account region/billing/login facts consistent, and document legitimate travel or enterprise network behavior.
