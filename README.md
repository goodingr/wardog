# wardog

An automated wireless auditing tool for **authorized** WPA/WPA2 security
testing: scans for nearby networks, then for each target attempts WPS
pixie-dust, PMKID capture, and full 4-way handshake capture (in that order),
and finally runs the results against a wordlist with hashcat.

> **Authorized use only.** Only point this at networks you own or have
> explicit written permission to test. Deauthenticating clients and
> attacking WPA/WPS on networks you don't control is illegal in most
> jurisdictions.

## Features

- **Interactive scan mode**: a live-updating table of nearby networks
  (signal strength, channel, encryption, WPS version/lock status, hidden
  SSIDs included) that you stop when ready and pick targets from.
- **Layered attack per target**:
  1. **WPS pixie-dust** (`reaver`) — recovers the actual WPA password
     directly when the AP has WPS enabled, skipping capture and cracking.
  2. **PMKID capture** — a fast, client-free attempt that doesn't require
     deauthenticating anyone.
  3. **Handshake capture** — deauths connected clients in rounds until a
     valid 4-way handshake is captured, with live progress as each EAPOL
     message (`M1 M2 (2/4)`) comes in.
- **Automated cracking**: runs hashcat against everything captured once
  you're done selecting targets.
- **Wardrive mode** (`--auto`): unattended, continuously scans and attacks
  every WPA network it finds.
- **Auto-configured adapters**: detects monitor-mode-capable wireless
  interfaces and switches them into monitor mode itself — no manual
  `airmon-ng` steps.

## Install

```bash
sudo apt install aircrack-ng hcxtools hashcat reaver iw wordlists
git clone https://github.com/goodingr/wardog.git
cd wardog
pipx install .
```

(`pipx` is recommended so wardog's Python dependencies stay isolated from
the rest of your system; `pip install --user .` works too.)

Requires a wireless adapter that supports monitor mode.

## Usage

```bash
wardog                # interactive mode: scan, then pick targets
wardog --auto         # wardrive mode: scans and attacks every WPA network it finds
wardog --help
```

Interactive mode shows a live table of networks as it scans:

```
  #   PWR   CH   ENC        WPS   LCK  ESSID                          BSSID
  1   -66   1    WPA2       2.0   No   MyHomeNetwork                  70:A7:41:AB:D7:26
  2   -73   6    WPA2       -     -    <hidden>                       A4:6B:1F:97:30:88
```

WPS/lock status comes from a concurrent `wash` scan and fills in as it's
discovered — a `-` just means nothing's been found yet (or the AP doesn't
have WPS enabled).

Stop the scan when ready and pick targets with a comma-separated list or
`all`. Each target then runs through WPS, PMKID, and handshake capture,
after which everything gets cracked against the configured wordlist.

Captured handshakes, PMKIDs, and recovered WPS passwords are written to
`~/.local/share/wardog/captures/`. Override the wordlist/rules file used
for cracking with `--wordlist`/`--rules`.

`--auto` (wardrive mode) attacks every WPA network it sees, unattended.
**Only use this where you've confirmed there are no neighboring networks
you don't own.**

## Known limitations

- **PMKID capture** uses `aireplay-ng`'s fake-authentication rather than
  `hcxdumptool`, for broader adapter compatibility. Because it's an
  open-system association rather than a full WPA handshake, many APs
  reject it outright and no PMKID is returned — wardog falls through to
  handshake capture in that case.
- **Deauth-based capture** depends on your adapter's packet injection
  support. Budget/embedded chipsets can be unreliable under sustained
  monitor-mode use; a well-supported adapter (e.g. Atheros- or
  RT3070-based) will perform significantly better.
- **Live WPS detection during scanning** uses a second wireless adapter
  when one is available, with no interference between it and the main
  scan. With only one adapter, both share it, and the channel-hopping
  contention between them means WPS results fill in slower and less
  completely than the dedicated per-target check wardog does before
  attacking (which isn't affected by this).

## Requirements

- Linux, with a wireless adapter that supports monitor mode
- Python 3.9+
- `sudo` access (wardog shells out to root-requiring tools for you)
- `aircrack-ng`, `hcxtools`, `hashcat`, `reaver`, `iw` (installed via apt, see above)

## License

MIT — see [LICENSE](LICENSE).
