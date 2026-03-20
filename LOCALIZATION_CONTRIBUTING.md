# Localization Contribution Guide

This guide is for contributors who want to add their native language to the Web Dashboard.

The dashboard reads languages from JSON files in:

`internal/dashboard/frontend/locales/`

Each locale is embedded into the Go binary, so adding a language means:

1. Fork the repository on GitHub.
2. Add a new locale JSON file.
3. Validate and test it locally.
4. Open a pull request.

## 1. Fork And Clone

Fork the repository on GitHub, then clone your fork:

```bash
git clone https://github.com/<your-user>/SSLInspectingRouter.git
cd SSLInspectingRouter
```

Create a branch for your translation:

```bash
git checkout -b add-locale-xx
```

Replace `xx` with your language code, for example `fr`, `de`, `it`, `uk`, `ja`.

## 2. Add A Locale File

Use the English file as the source template:

`internal/dashboard/frontend/locales/en.json`

Create a new file named with your locale code:

`internal/dashboard/frontend/locales/<code>.json`

Examples:

* `fr.json`
* `de.json`
* `pt-br.json`
* `uk.json`

### Locale File Rules

* Keep the JSON structure identical to `en.json`.
* Translate values only. Do not rename keys.
* Keep placeholders such as `{id}`, `{count}`, `{status}`, `{warning}` exactly as they are.
* Keep HTML snippets such as `<code>...</code>` intact where they already exist.
* Keep technical values like `WireGuard`, `Tor`, `PCAP`, `TLS`, `QUIC`, URLs, file paths, and API routes unchanged unless translation is clearly appropriate.
* Make sure `meta.code`, `meta.name`, and `meta.native_name` are filled in.

### Minimal Example

```json
{
  "meta": {
    "code": "fr",
    "name": "French",
    "native_name": "Français"
  },
  "strings": {
    "...": "..."
  }
}
```

## 3. Validate The JSON

Run:

```bash
python3 -m json.tool internal/dashboard/frontend/locales/<code>.json >/dev/null
```

This catches invalid JSON formatting.

## 4. Check That Your Locale Matches The English Keys

The new locale must contain the same translation keys as `en.json`.

## 5. Test The Dashboard

Rebuild the router binary so the embedded frontend includes your new locale:

```bash
./scripts/setup.sh
```

Start the dashboard:

```bash
sudo ./sslinspectingrouter -web :3000 
```

Then verify in the browser:

* your language appears in the language dropdown,
* switching to it reloads the UI,
* labels fit inside the layout,
* there are no untranslated English leftovers unless they are intentional technical terms.

## 6. Commit Your Changes

## 7. Open A Pull Request

Open a pull request from your fork to the main repository.

Include:

* the language you added,
* the locale code you used,
* confirmation that JSON validation passed.

## Translation Tips

* Prefer clear UI wording over literal word-for-word translation.
* Keep button labels short where possible.
* Use consistent wording for repeated concepts like `Save`, `Delete`, `Traffic`, `Users`, `Enabled`, and `Disabled`.
* If a phrase sounds too long for a button or dropdown, choose a shorter natural equivalent.

## Notes

* New languages do not need frontend code changes if they follow the existing locale file structure.
* The language dropdown is populated from the locale files automatically.
* Because the frontend is embedded, reviewers must rebuild the binary to see your new language.
