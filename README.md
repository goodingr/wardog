# wardog

An automated WPA handshake / PMKID / WPS capture pipeline for **authorized**
wireless security testing — essentially a wifite-style tool, built from
scratch to actually work reliably: real Ctrl+C handling, a live-updating
scan table, and honest reporting of what each attack actually achieved.

> **Authorized use only.** Only point this at networks you own or have
> explicit written permission to test. Deauthenticating clients and
> attacking WPA/WPS on networks you don't control is illegal in most
> jurisdictions.

## What it does

For each target, in order:

1. **WPS pixie-dust** (via `reaver`) — if the AP has WPS enabled, this can
   recover the actual WPA password directly, no capture or cracking needed.
2. **PMKID capture** — a fast, client-free, deauth-free attempt that elicits
   the AP's PMKID from a single fake association. Cheap to try, doesn't
   always succeed (see [Notes on reliability](#notes-on-reliability)).
3. **Handshake capture** — finds real connected clients and deauths them in
   rounds until a valid 4-way handshake is captured, printing live progress
   (`M1 M2 (2/4)`) as partial EAPOL messages come in.

Once you're done selecting targets, it cracks everything it captured against
a wordlist with hashcat.

Ctrl+C stops whatever is currently happening — the scan, or the attack on
the current target — and asks what to do next, instead of killing the whole
program.

## Install

```bash
sudo apt install aircrack-ng hcxtools hashcat reaver iw wordlists
git clone https://github.com/goodingr/wardog.git
cd wardog
pipx install .
```

(`pipx` is recommended so `wardog`'s Python dependencies stay isolated from
the rest of your system; `pip install --user .` works too.)

Requires a wireless adapter that supports monitor mode. `wardog` auto-detects
and configures your adapter(s) at startup — no manual `airmon-ng` dance
needed.

## Usage

```bash
wardog                # interactive: scan until Ctrl+C, then pick targets
wardog --auto         # wardrive mode: no prompts, attacks every WPA network it sees
wardog --help
```

In interactive mode, `wardog` scans continuously and shows a live table of
networks (press Ctrl+C when ready):

```
  #   PWR   CH   ENC        ESSID                          BSSID
  1   -66   1    WPA2       MyHomeNetwork                  70:A7:41:AB:D7:26
  2   -73   6    WPA2       <hidden>                       A4:6B:1F:97:30:88
```

Pick targets with a comma-separated list or `all`. While attacking a target,
Ctrl+C stops that attack and offers:

```
(s)kip to next target, (r)etry, (c)rack now & exit, (e)xit without cracking
```

Captured handshakes, PMKIDs, and recovered WPS passwords are written to
`~/.local/share/wardog/captures/` (override the wordlist/rules used for
cracking with `--wordlist`/`--rules`).

`--auto` runs unattended: continuously scans and attacks every WPA network
it finds, with no prompts. **Only use this where you've confirmed there are
no neighboring networks you don't own** — it will attack whatever it sees.

## Notes on reliability

This was built and tested against real hardware, and a couple of honest
limitations are baked into the behavior rather than papered over:

- **PMKID capture** uses `aireplay-ng --fakeauth` rather than the more
  purpose-built `hcxdumptool`, because `hcxdumptool` captures zero packets
  on some older/limited monitor-mode drivers (confirmed on RTL8188EU/
  `rtl8xxxu`). `aireplay-ng`'s plain fake-authentication is open-system only,
  so many modern APs reject the association outright (`Association denied
  (code 40)`) without ever sending a PMKID-bearing frame. When that happens,
  wardog just falls through to full handshake capture — this is expected,
  not a bug.
- Effectiveness of deauth-based capture depends heavily on your adapter's
  injection support. Cheap/embedded chipsets (again, RTL8188EU) can be
  flaky under sustained monitor-mode + injection use; a well-supported
  adapter (e.g. an Atheros- or RT3070-based one) will be far more reliable.

## Requirements

- Linux, with a wireless adapter that supports monitor mode
- Python 3.9+
- `sudo` access (wardog shells out to root-requiring tools for you)
- `aircrack-ng`, `hcxtools`, `hashcat`, `reaver`, `iw` (installed via apt, see above)

## License

MIT — see [LICENSE](LICENSE).
