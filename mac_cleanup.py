#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mac_cleanup.py  -  See what is eating disk, memory and CPU on your Mac, learn what each
thing is (macOS system / needed / optional / bloat), and clean it up from an
interactive report in your browser.

USAGE
  python3 mac_cleanup.py              Full scan, then opens the interactive report
  python3 mac_cleanup.py --quick      Skip the slow scans (project deps, large-file search)
  python3 mac_cleanup.py --no-serve   Static HTML report only (no delete buttons; you can
                                      export the selected items as a shell script instead)
  python3 mac_cleanup.py --min-mb 50  Hide items smaller than 50 MB (default 25)
  python3 mac_cleanup.py --port 8765  Use a fixed port for the local report server

REQUIREMENTS
  macOS 12+ (Apple silicon or Intel), Python 3.9+ (the one from Xcode Command Line Tools
  is fine). No third-party packages.

  For complete results give your terminal app Full Disk Access:
  System Settings > Privacy & Security > Full Disk Access > enable Terminal / iTerm / Zed.
  Without it, Mail, Messages, Safari, Trash and some app containers show as 0 or are skipped.

SAFETY MODEL
  * The scan never changes anything. Deletion only happens after you select items in the
    report and confirm.
  * Default action is "Move to Trash" (everything goes into one dated folder in the Trash,
    with a RESTORE.txt listing the original locations). Permanent delete is opt-in.
  * The browser only sends item IDs. The local server only acts on paths and commands
    that the scan found itself, and re-checks every path against a protected-location list
    (/System, /usr, /bin, ~/Library itself, iCloud Drive, Photos libraries, SIP apps...).
  * The server listens on 127.0.0.1 only and requires a random per-run token.
  * Root-owned items trigger the normal macOS administrator password dialog (once per batch).
  * Every action is logged to ~/mac_cleanup_reports/actions.log
"""
from __future__ import annotations

import argparse
import datetime as dt
import errno
import getpass
import glob
import json
import os
import plistlib
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.0"
HOME = os.path.expanduser("~")
LIB = os.path.join(HOME, "Library")
AS = os.path.join(LIB, "Application Support")
CACHES = os.path.join(LIB, "Caches")
CONTAINERS = os.path.join(LIB, "Containers")
GROUPC = os.path.join(LIB, "Group Containers")
UID = os.getuid()
ME = getpass.getuser()
MB = 1024 ** 2
GB = 1024 ** 3
NOW = time.time()
REPORT_DIR = os.path.join(HOME, "mac_cleanup_reports")
SF_RESTRICTED = 0x00080000  # SIP "restricted" file flag

# Homebrew & friends are often missing from PATH when launched from a GUI.
for _p in ("/opt/homebrew/bin", "/usr/local/bin", os.path.join(HOME, ".orbstack/bin")):
    if _p not in os.environ.get("PATH", ""):
        os.environ["PATH"] = os.environ.get("PATH", "") + ":" + _p

ARGS = None
SCAN_WARNINGS = []


# ----------------------------------------------------------------------------- helpers
def sh(cmd, timeout=60):
    """Run a command (argv list). Returns (rc, stdout, stderr); never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as e:  # pragma: no cover
        return 1, "", str(e)


def have(cmd):
    return shutil.which(cmd) is not None


def human(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or u == "TB":
            return ("%.0f %s" if u in ("B", "KB") else "%.1f %s") % (n, u)
        n /= 1024.0


def say(msg):
    print(msg, flush=True)


def read_plist(path):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return {}


def listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def days_ago(ts):
    return None if not ts else int((NOW - ts) / 86400)


def q(s):
    return shlex.quote(s)


# ----------------------------------------------------------------------------- sizes
DU_MAP = {}
_du_done = threading.Event()


def du_home_tree(depth=3, timeout=900):
    """One `du` pass over the home folder, keeping totals down to `depth` levels."""
    try:
        p = subprocess.Popen(["du", "-k", "-d", str(depth), HOME], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, errors="replace")
    except Exception:
        _du_done.set()
        return
    deadline = time.time() + timeout

    def killer():
        while p.poll() is None:
            if time.time() > deadline:
                p.kill()
                SCAN_WARNINGS.append("Home-folder size scan hit its time limit; some sizes are partial.")
                return
            time.sleep(1)

    threading.Thread(target=killer, daemon=True).start()
    for line in p.stdout:
        try:
            k, path = line.rstrip("\n").split("\t", 1)
            DU_MAP[path] = int(k) * 1024
        except ValueError:
            pass
    p.wait()
    _du_done.set()


def size_of(path, timeout=300):
    if path in DU_MAP:
        return DU_MAP[path]
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    if not stat.S_ISDIR(st.st_mode):
        return st.st_blocks * 512  # real allocated size (handles sparse files like Docker.raw)
    rc, out, _ = sh(["du", "-sk", path], timeout=timeout)
    try:
        return int(out.strip().splitlines()[-1].split("\t")[0]) * 1024
    except Exception:
        return 0


def sizes(paths, workers=8):
    paths = list(paths)
    with ThreadPoolExecutor(workers) as ex:
        return dict(zip(paths, ex.map(size_of, paths)))


# ----------------------------------------------------------------------------- items
ITEMS = {}   # id -> public dict (sent to the browser)
PRIV = {}    # id -> private action details (never sent)
SEEN = set()
_lock = threading.Lock()


def add_item(section, name, kind="path", path="", size=0, safety="review", category="",
             impact="", note="", action=None, meta=None, export="", priv=None):
    with _lock:
        iid = "i%d" % (len(ITEMS) + 1)
        ITEMS[iid] = dict(id=iid, section=section, name=name, kind=kind, path=path,
                          size=int(size or 0), safety=safety, category=category, impact=impact,
                          note=note, action=action,
                          deletable=bool(action) and safety not in ("protected", "info"),
                          meta=meta or {}, export=export, status=None)
        PRIV[iid] = priv or {}
    return iid


def _covered(path):
    p = path
    while p and p != "/":
        if p in SEEN:
            return True
        p = os.path.dirname(p)
    return False


def add_path(section, path, name, category, safety, impact, contents_only=False, size=None,
             note="", meta=None, min_bytes=0, info=False, admin=False):
    if not path or not os.path.lexists(path) or _covered(path):
        return None
    sz = size_of(path) if size is None else size
    if sz < min_bytes:
        return None
    SEEN.add(path)
    if info:
        return add_item(section, name, kind="info", path=path, size=sz, safety="info",
                        category=category, impact=impact, note=note, meta=meta)
    if contents_only:
        export = "find %s -mindepth 1 -maxdepth 1 -exec mv {} ~/.Trash/ \\;" % q(path)
    else:
        export = "mv %s ~/.Trash/" % q(path)
    if admin:
        export = "sudo " + export.replace("~/.Trash/", q(HOME + "/.Trash/"))
    return add_item(section, name, kind="path", path=path, size=sz, safety=safety,
                    category=category, impact=impact, note=note, meta=meta,
                    action="Clear contents" if contents_only else "Remove", export=export,
                    priv=dict(paths=[path], contents_only=contents_only))


def add_cmd(section, name, cmd, category, safety, impact, size=0, admin=False, note="",
            path="", order=0, meta=None, timeout=900):
    export = ("sudo " if admin else "") + " ".join(q(c) for c in cmd)
    return add_item(section, name, kind="command", path=path, size=size, safety=safety,
                    category=category, impact=impact, note=note, action="Run", export=export,
                    meta=meta, priv=dict(cmd=cmd, admin=admin, order=order, timeout=timeout))


# ----------------------------------------------------------------------------- protection
PROTECTED_PARENTS = {"/", "/Library", "/Users", "/private", "/private/var", "/opt", "/Volumes",
                     "/System", "/usr", HOME, LIB}
PROTECTED_EXACT = {"/Applications", "/Applications/Utilities", "/Applications/Safari.app",
                   "/opt/homebrew", "/usr/local"}
PROTECTED_PREFIXES = ("/System/", "/usr/", "/bin/", "/sbin/", "/private/var/db/",
                      "/private/var/vm/", "/Library/Apple/", "/dev/", "/cores/",
                      os.path.join(LIB, "Mobile Documents") + "/",
                      os.path.join(LIB, "CloudStorage") + "/",
                      os.path.join(LIB, "Keychains") + "/")


def path_is_safe(p):
    """Final guard before anything is moved or deleted."""
    if not p or not os.path.isabs(p):
        return False
    p = os.path.normpath(p)
    if p in PROTECTED_PARENTS or p in PROTECTED_EXACT:
        return False
    if os.path.dirname(p) in PROTECTED_PARENTS:
        return False
    if any((p + "/").startswith(x) for x in PROTECTED_PREFIXES):
        return False
    if (HOME + "/").startswith(p + "/"):
        return False
    if p.startswith("/Users/") and not p.startswith(HOME + "/"):
        return False   # never touch other users' files
    if ".photoslibrary" in p or ".musiclibrary" in p:
        return False
    return True


# ============================================================================ KNOWLEDGE
# (regex on lowercase process name/path, explanation)
KNOWN_PROCS = [
    (r"^kernel_task$", "macOS kernel. High CPU here usually means macOS is deliberately throttling to cool the Mac (heat, charging, many displays). Cannot be quit."),
    (r"^windowserver$", "Draws everything on screen. Grows with many open windows, external/high-res displays and transparency effects. Cannot be quit."),
    (r"^(mds|mds_stores|mdworker.*|mdsync|corespotlightd|spotlightknowledged)$", "Spotlight indexing. Spikes after updates or big file changes, then settles. Tip: add node_modules / vendor / Docker / model folders to System Settings > Spotlight > Search Privacy."),
    (r"^(photoanalysisd|mediaanalysisd|photolibraryd|photosreliveryd)$", "Photos library analysis (faces, objects, memories). Runs while idle/charging and is temporary."),
    (r"^(bird|cloudd|fileproviderd|nsurlsessiond|clouddocs.*)$", "iCloud sync / background downloads."),
    (r"^backupd", "Time Machine backup in progress."),
    (r"softwareupdate|mobilesoftwareupdate", "Downloading or preparing macOS updates."),
    (r"webkit\.webcontent|webkit\.gpu|webkit\.networking", "Web page content for Safari or an app's web view (one process per tab/site). Close heavy tabs to free memory."),
    (r"google chrome|chrome helper", "Chrome and its tabs/extensions (one helper per tab or extension). Window > Task Manager inside Chrome shows heavy tabs; enable Memory Saver in Chrome settings."),
    (r"microsoft edge|edge helper", "Edge and its tabs/extensions. Use Edge's Task Manager (Shift+Esc) for heavy tabs."),
    (r"firefox|plugin-container", "Firefox and its content processes. about:processes shows heavy tabs."),
    (r"com\.docker|docker desktop|docker|virtualization\.virtualmachine|qemu|vmnetd", "Docker Desktop's Linux VM. Memory is reserved by the VM: lower it in Docker Desktop > Settings > Resources, or quit Docker when you are not using containers."),
    (r"orbstack", "OrbStack VM (Docker/Linux). Memory is used by the VM's containers."),
    (r"^ollama", "Ollama server. Its memory is the loaded model(s). `ollama ps` lists them, `ollama stop <model>` unloads; models unload after 5 min idle by default."),
    (r"lm studio|lmstudio", "LM Studio. Memory is the loaded model; eject it in LM Studio when done."),
    (r"^node$", "Node.js process: dev servers, build watchers, language servers. Check for a forgotten `npm run dev`."),
    (r"^(php|php-fpm|php\d.*)$", "PHP process (artisan serve, queue workers, Valet/Herd PHP-FPM)."),
    (r"^python", "Python process (scripts, Jupyter, language servers)."),
    (r"^java$", "Java process (IDE language servers, Gradle daemon, Elasticsearch...)."),
    (r"^(syspolicyd|trustd|xprotect.*|amfid)$", "Security checks of apps and certificates (Gatekeeper / XProtect). Part of macOS."),
    (r"^logd$", "System logging service."),
    (r"^coreaudiod$", "System audio. High CPU while audio plays or with audio plug-ins."),
    (r"^launchd$", "The first process; starts and supervises everything else."),
    (r"^zed", "Zed editor (incl. its language servers)."),
    (r"code helper|^electron|visual studio code", "Electron/VS Code helper processes (renderers, extensions, language servers)."),
    (r"teams|msteams", "Microsoft Teams. Known to be memory hungry; quit when not in meetings."),
    (r"slack", "Slack (Electron). Quit or sign out of unused workspaces to save memory."),
    (r"falcon|crowdstrike|sentinel|jamf|zscaler|netskope|forcepoint|wdav|defender|globalprotect|anyconnect|cisco secure|intune|companyportal|tanium|carbonblack|trellix|fortinet|kandji|mosyle",
     "Security / VPN / device-management software installed by your organization. Do not stop it; ask IT if it misbehaves."),
    (r"^(finder|dock|systemuiserver|controlcenter|loginwindow|notificationcenter)$", "Core macOS user-interface process. Relaunches automatically if killed."),
    (r"^(cfprefsd|distnoted|usernoted|secd|sharingd|rapportd|bluetoothd|airportd|powerd|configd|opendirectoryd|hidd|coreservicesd)$", "macOS system service."),
]

KNOWN_AGENTS = [
    # (regex on label, vendor, what it does, safety, impact)
    (r"^com\.apple\.", "Apple", "macOS component", "protected", "Part of macOS."),
    (r"crowdstrike|sentinelone|com\.jamf|com\.microsoft\.(wdav|dlp|intune|companyportal)|paloaltonetworks|com\.cisco\.(anyconnect|secureclient)|zscaler|netskope|forcepoint|tanium|carbonblack|com\.kandji|mosyle|trendmicro|trellix|fortinet|com\.vmware\.carbonblack|com\.symantec\.dlp",
     "Your organization", "Security / VPN / device management", "caution",
     "Managed by your IT department. Removing it can break VPN or network access, violate company policy, or be reinstalled automatically. Ask IT instead."),
    (r"mackeeper|zeobit|kromtech|com\.mac(auto|clean)|advancedmaccleaner|com\.pcv|searchbaron|com\.genieo|com\.vsearch|installmac|com\.mughthesec",
     "Adware / PUP", "Potentially unwanted program", "safe",
     "Widely classified as adware / potentially unwanted software. Removing it is recommended."),
    (r"keystone|com\.google\.googleupdater|com\.google\.updater", "Google", "Google Software Update", "review",
     "Chrome / Google Drive stop updating automatically (you miss security fixes until you update manually). Chrome may re-create it when launched."),
    (r"com\.microsoft\.(update|autoupdate)", "Microsoft", "Microsoft AutoUpdate", "review",
     "Office / Teams / Edge stop auto-updating; update manually from the Help menu."),
    (r"com\.adobe\.", "Adobe", "Adobe background service (Creative Cloud, licensing, updates)", "review",
     "Creative Cloud sync, license checks and updates stop running in the background. Adobe apps may complain or re-install it."),
    (r"zoom", "Zoom", "Zoom updater / daemon", "review", "Zoom stops auto-updating; meetings still work."),
    (r"dropbox", "Dropbox", "Dropbox helper", "review", "Dropbox no longer starts or syncs at login."),
    (r"spotify", "Spotify", "Spotify helper", "safe", "Spotify no longer pre-launches; it still works when opened."),
    (r"com\.oracle\.java", "Oracle", "Java updater", "safe", "Java stops checking for updates."),
    (r"teamviewer|anydesk|splashtop|logmein", "Remote access", "Remote-access service", "review",
     "Remote access to this Mac stops unless you open the app manually."),
    (r"com\.docker", "Docker", "Docker privileged helper (networking / socket)", "review",
     "Needed by Docker Desktop. Remove only if you no longer use Docker."),
    (r"logi|logitech", "Logitech", "Logitech device helper", "review", "Custom mouse/keyboard buttons & settings stop working."),
    (r"paragon|tuxera", "Paragon / Tuxera", "NTFS file-system driver helper", "review", "Writing to NTFS drives stops working."),
    (r"avast|avg|norton|symantec|mcafee|kaspersky|bitdefender|eset|sophos|malwarebytes|intego|clamxav",
     "Antivirus", "Third-party antivirus", "review",
     "Background scanning stops. macOS has XProtect/Gatekeeper built in; keep only if you need it (check with IT on a work Mac)."),
    (r"grammarly", "Grammarly", "Grammarly desktop helper", "safe", "Grammarly no longer runs system-wide at login."),
    (r"parallels|vmware", "VM software", "Virtualization helper", "review", "Needed by Parallels/VMware for networking and USB."),
    (r"nordvpn|expressvpn|surfshark|protonvpn|tunnelblick|wireguard", "VPN", "VPN helper", "review", "That VPN app will not connect until reinstalled/re-enabled."),
    (r"steam|valvesoftware|epicgames|battle\.net|blizzard", "Game launcher", "Game launcher helper", "safe", "Launcher no longer starts at login."),
    (r"^homebrew\.mxcl\.", "Homebrew", "`brew services` background service", "review",
     "A Homebrew service (e.g. mysql, redis, php). Prefer `brew services stop <name>`."),
]

BLOAT_APPS = [
    # (regex on lowercase app name or bundle id, category, safety, note)
    (r"mackeeper|advanced mac cleaner|mac auto fixer|mac cleanup pro|smart mac booster|mac ?tonic|mac mechanic|pc keeper|tuneupmymac|mac ?booster|similar photo cleaner|genieo|searchbaron|mplayerx",
     "Adware / PUP", "safe", "Widely classified as adware or a potentially unwanted 'optimizer'. Removing it is recommended."),
    (r"crowdstrike|falcon|sentinel|jamf|zscaler|netskope|forcepoint|microsoft defender|globalprotect|cisco (anyconnect|secure client)|company portal|tanium|carbon ?black|trellix|forticlient|kandji|mosyle|self service",
     "Managed by organization", "caution", "Security / VPN / device-management software from your IT department. Do not remove without IT approval."),
    (r"avast|avg |norton|mcafee|kaspersky|bitdefender|eset|sophos|intego|clamxav|totalav|malwarebytes",
     "Antivirus", "review", "Third-party antivirus with always-on background scanners. macOS already has XProtect & Gatekeeper; keep only if required."),
    (r"cleanmymac|ccleaner|onyx|daisydisk|app cleaner|appcleaner",
     "Cleaner utility", "review", "Optional cleaning utility. Not harmful, but often keeps a menu-bar agent running."),
]

APPLE_OPTIONAL = {
    "com.apple.garageband10": "Free from the App Store. Its sound library (/Library/Application Support/GarageBand, Apple Loops) can be several GB and is listed under Storage.",
    "com.apple.imovieapp": "Free from the App Store; reinstall any time.",
    "com.apple.iwork.keynote": "Free from the App Store; reinstall any time.",
    "com.apple.iwork.pages": "Free from the App Store; reinstall any time.",
    "com.apple.iwork.numbers": "Free from the App Store; reinstall any time.",
    "com.apple.dt.xcode": "Needed for iOS/macOS development. For git/clang/Homebrew the much smaller Command Line Tools are enough.",
    "com.apple.logic10": "Paid app; reinstall from your App Store purchases. Its sound library is separate.",
    "com.apple.finalcut": "Paid app; reinstall from your App Store purchases.",
    "com.apple.mainstage3": "Paid app; reinstall from your App Store purchases.",
    "com.apple.configurator2": "Apple Configurator; free from the App Store.",
}

DEV_CACHES = {  # ~/Library/Caches/<name>
    "pip": ("pip download cache", "Python packages re-download on the next pip install."),
    "Yarn": ("Yarn cache", "Packages re-download on the next yarn install."),
    "composer": ("Composer cache", "PHP packages re-download on the next composer install (first install is slower)."),
    "node-gyp": ("node-gyp headers", "Node native-addon headers re-download when needed."),
    "ms-playwright": ("Playwright browsers", "Test browsers; `npx playwright install` re-downloads them."),
    "JetBrains": ("JetBrains IDE caches", "IDEs (PhpStorm, etc.) re-index projects on next open, which can take a few minutes."),
    "go-build": ("Go build cache", "Go rebuilds packages on the next build."),
    "CocoaPods": ("CocoaPods cache", "Pods re-download on the next pod install."),
    "pypoetry": ("Poetry cache", "Packages re-download on the next poetry install."),
    "typescript": ("TypeScript type cache", "Re-created by editors automatically."),
    "Cypress": ("Cypress binaries", "Re-downloaded on next `npx cypress install`."),
    "electron": ("Electron downloads", "Re-downloaded by build tools when needed."),
    "electron-builder": ("electron-builder cache", "Re-downloaded by build tools when needed."),
    "pnpm": ("pnpm metadata cache", "Re-created on the next pnpm install."),
    "deno": ("Deno cache", "Modules re-download on next run."),
    "Homebrew": None,  # handled by `brew cleanup`
}

SPACE_INFO = {
    "Library": "App data, caches, settings, mail, messages. Broken down below.",
    "Library/Application Support": "Per-app data (settings, databases, downloaded content).",
    "Library/Containers": "Data of sandboxed apps (App Store & Apple apps). One folder per app.",
    "Library/Group Containers": "Data shared between an app and its extensions (Office, WhatsApp, Telegram, Notes...).",
    "Library/Caches": "Rebuildable caches. Listed individually under Storage & caches.",
    "Library/Mobile Documents": "iCloud Drive files kept on this Mac. Turn on 'Optimize Mac Storage' (System Settings > Apple ID > iCloud > Drive) to let macOS evict them.",
    "Library/Messages": "iMessage history and attachments. Use Messages > Settings > Keep messages: 1 year, or System Settings > General > Storage > Messages.",
    "Library/Mail": "Mail.app messages and attachments. Manage mailboxes inside Mail.",
    "Library/Developer": "Xcode builds, simulators and device support. Listed under Developer & AI.",
    "Library/CloudStorage": "Files from Google Drive / OneDrive / Dropbox kept offline on this Mac. Manage from those apps.",
    "Library/Photos": "Photos-related data.",
    "Pictures": "Your pictures, including the Photos library (manage in Photos; enable 'Optimize Mac Storage').",
    "Movies": "Your videos (incl. iMovie/Final Cut libraries).",
    "Music": "Your music (incl. GarageBand projects).",
    "Downloads": "Your downloads. Large/old files are listed under Large files & Downloads.",
    "Documents": "Your documents (may be synced with iCloud Drive).",
    "Desktop": "Your desktop files (may be synced with iCloud Drive).",
    ".ollama": "Ollama local AI models. Per-model cleanup under Developer & AI.",
    ".docker": "Docker CLI config & buildx data.",
    ".npm": "npm cache. Listed under Developer & AI.",
    ".cache": "Developer tool caches (Hugging Face, pre-commit, etc.).",
    ".Trash": "Items already in the Trash.",
    ".gradle": "Gradle caches & wrappers.",
    ".m2": "Maven repository.",
    ".cargo": "Rust toolchain & crates.",
    ".rustup": "Rust toolchains.",
    ".nvm": "Node versions installed via nvm (each ~100-200 MB).",
    ".pyenv": "Python versions installed via pyenv.",
    ".lmstudio": "LM Studio models.",
    ".vscode": "VS Code extensions.",
    ".composer": "Composer global packages & cache.",
    ".orbstack": "OrbStack VM data.",
}


def proc_explain(name, path):
    n = name.lower()
    hay = (n + " " + path.lower())
    for rx, txt in KNOWN_PROCS:
        if re.search(rx, n) or (not rx.startswith("^") and re.search(rx, hay)):
            return txt
    return ""


def classify_agent(label, prog):
    hay = (label + " " + (prog or "")).lower()
    for rx, vendor, what, safety, impact in KNOWN_AGENTS:
        if re.search(rx, label.lower()) or (rx != r"^com\.apple\." and re.search(rx, hay)):
            return vendor, what, safety, impact
    return None


# ============================================================================ SYSTEM INFO
SYS = {}


def scan_system():
    def sysctl(k):
        return sh(["sysctl", "-n", k])[1].strip()
    SYS["model"] = sysctl("hw.model")
    SYS["cpu"] = sysctl("machdep.cpu.brand_string")
    try:
        SYS["cores"] = int(sysctl("hw.ncpu") or os.cpu_count() or 1)
    except ValueError:
        SYS["cores"] = os.cpu_count() or 1
    try:
        SYS["mem_total"] = int(sysctl("hw.memsize"))
    except ValueError:
        SYS["mem_total"] = 0
    rc, out, _ = sh(["sw_vers"])
    m = dict(re.findall(r"(\w+):\s*(.+)", out))
    SYS["macos"] = ("%s %s (%s)" % (m.get("ProductName", "macOS"), m.get("ProductVersion", ""), m.get("BuildVersion", ""))).strip()
    bt = re.search(r"sec = (\d+)", sysctl("kern.boottime"))
    SYS["uptime_days"] = round((NOW - int(bt.group(1))) / 86400, 1) if bt else None
    SYS["load"] = list(os.getloadavg())
    data_vol = "/System/Volumes/Data" if os.path.isdir("/System/Volumes/Data") else "/"
    du_ = shutil.disk_usage(data_vol)
    SYS["disk"] = dict(total=du_.total, used=du_.total - du_.free, free=du_.free)
    # Full Disk Access check
    for probe in (os.path.join(LIB, "Mail"), os.path.join(LIB, "Safari"), os.path.join(HOME, ".Trash")):
        if os.path.isdir(probe):
            try:
                os.listdir(probe)
            except PermissionError:
                SCAN_WARNINGS.append("Your terminal does not have Full Disk Access, so Mail, Messages, Safari, Trash and some app data could not be measured. "
                                     "Enable it in System Settings > Privacy & Security > Full Disk Access, then re-run.")
                break


def scan_memory():
    mem = {}
    rc, out, _ = sh(["vm_stat"])
    ps_ = re.search(r"page size of (\d+)", out)
    page = int(ps_.group(1)) if ps_ else 16384
    vals = {k.strip(): int(v) for k, v in re.findall(r"^([^:]+):\s+(\d+)\.", out, re.M)}

    def pg(k):
        return vals.get(k, 0) * page
    mem["wired"] = pg("Pages wired down")
    mem["compressed"] = pg("Pages occupied by compressor")
    mem["app"] = max(0, pg("Anonymous pages") - pg("Pages purgeable"))
    mem["cached"] = pg("File-backed pages") + pg("Pages purgeable")
    mem["free"] = pg("Pages free")
    mem["used"] = mem["wired"] + mem["compressed"] + mem["app"]
    rc, out, _ = sh(["sysctl", "-n", "vm.swapusage"])
    m = re.search(r"total = ([\d.]+)M\s+used = ([\d.]+)M", out)
    mem["swap_total"] = int(float(m.group(1)) * MB) if m else 0
    mem["swap_used"] = int(float(m.group(2)) * MB) if m else 0
    rc, out, _ = sh(["memory_pressure", "-Q"], timeout=15)
    m = re.search(r"free percentage:\s*(\d+)%", out)
    mem["free_pct"] = int(m.group(1)) if m else None
    mem["total"] = SYS.get("mem_total", 0)
    SYS["memory"] = mem


# ============================================================================ PROCESSES
def parse_cputime(s):
    days = 0
    if "-" in s:
        d, s = s.split("-", 1)
        days = int(d)
    secs = 0.0
    for part in s.split(":"):
        try:
            secs = secs * 60 + float(part)
        except ValueError:
            return 0.0
    return days * 86400 + secs


def ps_snapshot():
    rc, out, _ = sh(["ps", "-axo", "pid=,ppid=,user=,%cpu=,%mem=,rss=,time=,comm="])
    rows = {}
    for line in out.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8:
            continue
        try:
            pid = int(parts[0])
            rows[pid] = dict(pid=pid, user=parts[2], cpu_avg=float(parts[3]), rss=int(parts[5]) * 1024,
                             cputime=parse_cputime(parts[6]), comm=parts[7])
        except ValueError:
            continue
    return rows


def app_bundle_of(comm):
    m = re.match(r"^(.*?/[^/]+\.app)/", comm)
    return m.group(1) if m else None


RUNNING_APPS = set()
PROC_SUMMARY = {}


def scan_processes(sample=2.0):
    s1 = ps_snapshot()
    t1 = time.time()
    time.sleep(sample)
    s2 = ps_snapshot()
    el = max(0.5, time.time() - t1)
    groups = {}
    for pid, r in s2.items():
        prev = s1.get(pid)
        r["cpu_now"] = max(0.0, (r["cputime"] - prev["cputime"]) / el * 100) if prev else 0.0
        app = app_bundle_of(r["comm"])
        if app:
            RUNNING_APPS.add(app)
        key = app or r["comm"]
        g = groups.setdefault(key, dict(key=key, app=app, procs=[], rss=0, cpu_now=0.0, cpu_avg=0.0, users=set()))
        g["procs"].append(r)
        g["rss"] += r["rss"]
        g["cpu_now"] += r["cpu_now"]
        g["cpu_avg"] += r["cpu_avg"]
        g["users"].add(r["user"])

    sys_prefixes = ("/System/Library/", "/System/iOSSupport/", "/usr/", "/sbin/", "/bin/", "/Library/Apple/",
                    "/private/", "/System/Cryptexes/", "/Library/Developer/CommandLineTools/")
    rows = sorted(groups.values(), key=lambda g: -g["rss"])
    total_cpu = sum(g["cpu_now"] for g in rows)
    PROC_SUMMARY["total_cpu_now"] = total_cpu
    PROC_SUMMARY["nprocs"] = len(s2)
    PROC_SUMMARY["top_mem"] = []
    PROC_SUMMARY["top_cpu"] = []
    shown = 0
    for g in rows:
        if not (g["rss"] >= 50 * MB or g["cpu_now"] >= 2 or g["cpu_avg"] >= 5):
            continue
        if shown >= 90:
            break
        shown += 1
        path = g["app"] or g["key"]
        name = os.path.basename(path)[:-4] if g["app"] else os.path.basename(path)
        expl = proc_explain(name, path)
        org = "organization" in expl
        bid = ""
        if g["app"]:
            bid = str(read_plist(os.path.join(g["app"], "Contents/Info.plist")).get("CFBundleIdentifier", ""))
        if name in ("kernel_task", "launchd") or (path.startswith(sys_prefixes) and not path.startswith("/System/Applications")):
            kind, safety, action = "macOS system", "protected", None
        elif org:
            kind, safety, action = "Managed by organization", "protected", None
        elif path.startswith("/System/Applications") or path == "/Applications/Safari.app":
            kind, safety, action = "Apple app", "review", "Quit"
        elif g["users"] != {ME}:
            kind, safety, action = "Background service (root/other user)", "protected", None
            if not expl:
                expl = "Third-party service running as root. If you do not want it, remove its launch item under Background items."
        elif g["app"]:
            kind, safety, action = "App", "review", "Quit"
        else:
            kind, safety, action = "Process", "review", "Kill"
        if not expl:
            expl = {"App": "Regular app you can quit; it closes its windows (may ask to save documents).",
                    "Apple app": "Built-in Apple app; quitting is harmless.",
                    "Process": "Command-line/background process started by you or an app. Killing it stops it (unsaved work in it is lost)."}.get(kind, "Part of macOS.")
        impact = expl
        if action == "Quit":
            impact += " Frees about %s of memory." % human(g["rss"])
        meta = dict(cpu_now=round(g["cpu_now"], 1), cpu_avg=round(g["cpu_avg"], 1), nprocs=len(g["procs"]),
                    kind=kind, cores=SYS.get("cores", 1))
        add_item("processes", name, kind="process", path=path, size=g["rss"], safety=safety, category=kind,
                 impact=impact, action=action, meta=meta,
                 export=("osascript -e 'tell application id \"%s\" to quit'" % bid) if (bid and action) else
                        ("kill " + " ".join(str(p["pid"]) for p in g["procs"]) if action else ""),
                 priv=dict(pids=[(p["pid"], p["comm"]) for p in g["procs"]], bid=bid, tries=0))
        PROC_SUMMARY["top_mem"].append((name, g["rss"]))
        PROC_SUMMARY["top_cpu"].append((name, g["cpu_now"]))
    PROC_SUMMARY["top_mem"] = PROC_SUMMARY["top_mem"][:6]
    PROC_SUMMARY["top_cpu"] = sorted(PROC_SUMMARY["top_cpu"], key=lambda x: -x[1])[:6]

    # Ollama loaded models -> unload
    if have("ollama"):
        rc, out, _ = sh(["ollama", "ps"], timeout=10)
        for line in out.splitlines()[1:]:
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 3 and parts[0]:
                add_cmd("processes", "Unload Ollama model %s" % parts[0], ["ollama", "stop", parts[0]],
                        "Loaded AI model", "safe",
                        "Frees the RAM/GPU memory held by this model (%s). It reloads automatically (a few seconds) on the next request." % parts[2],
                        size=parse_size_str(parts[2]))
    add_cmd("processes", "Purge inactive disk cache (purge)", ["purge"], "Memory", "review",
            "Flushes the file cache. macOS manages this memory itself and refills it quickly, so the effect is temporary; useful only before benchmarking. Asks for your password.",
            admin=True)


def parse_size_str(s):
    m = re.match(r"([\d.]+)\s*([KMGT]?)B", s.strip(), re.I)
    if not m:
        return 0
    mult = {"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[m.group(2).upper()]
    return int(float(m.group(1)) * mult)


# ============================================================================ APPLICATIONS
APPS = []
INSTALLED_BIDS = set()
INSTALLED_VENDORS = set()
BID_TO_NAME = {}


def vendor_of(bid):
    parts = bid.lower().split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else bid.lower()


def last_used(p):
    rc, out, _ = sh(["mdls", "-raw", "-name", "kMDItemLastUsedDate", p], timeout=15)
    out = out.strip()
    if rc != 0 or not out or out == "(null)":
        return None
    try:
        return dt.datetime.strptime(out[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return None


def support_paths(bid, name):
    c = []
    if bid:
        c += [os.path.join(AS, bid), os.path.join(CACHES, bid), os.path.join(CONTAINERS, bid),
              os.path.join(LIB, "Saved Application State", bid + ".savedState"),
              os.path.join(LIB, "HTTPStorages", bid), os.path.join(LIB, "HTTPStorages", bid + ".binarycookies"),
              os.path.join(LIB, "WebKit", bid), os.path.join(LIB, "Preferences", bid + ".plist"),
              os.path.join(LIB, "Logs", bid), os.path.join(LIB, "Application Scripts", bid),
              os.path.join(GROUPC, "group." + bid)]
        c += glob.glob(os.path.join(GROUPC, "*." + bid))
        c += glob.glob(os.path.join(LIB, "LaunchAgents", glob.escape(bid) + "*.plist"))
    if name and not bid.startswith("com.apple."):
        c += [os.path.join(AS, name), os.path.join(CACHES, name), os.path.join(LIB, "Logs", name)]
    out = []
    for p in c:
        if p not in out and os.path.lexists(p) and path_is_safe(p):
            out.append(p)
    return out


def scan_apps():
    roots = ["/Applications", os.path.join(HOME, "Applications")]
    paths = []
    for r in roots:
        paths += glob.glob(os.path.join(r, "*.app"))
        paths += [p for p in glob.glob(os.path.join(r, "*", "*.app")) if not os.path.dirname(p).endswith(".app")]
    for p in paths:
        info = read_plist(os.path.join(p, "Contents/Info.plist"))
        bid = str(info.get("CFBundleIdentifier", ""))
        name = os.path.basename(p)[:-4]
        APPS.append(dict(path=p, name=name, bid=bid, version=str(info.get("CFBundleShortVersionString", ""))))
        if bid:
            INSTALLED_BIDS.add(bid.lower())
            INSTALLED_VENDORS.add(vendor_of(bid))
            BID_TO_NAME[bid.lower()] = name
    say("   %d apps found, measuring sizes and last-used dates..." % len(APPS))
    szs = sizes([a["path"] for a in APPS])
    with ThreadPoolExecutor(8) as ex:
        lu = dict(zip([a["path"] for a in APPS], ex.map(last_used, [a["path"] for a in APPS])))

    for a in APPS:
        p, name, bid = a["path"], a["name"], a["bid"]
        a["size"] = szs.get(p, 0)
        a["last_used"] = lu.get(p)
        bl = bid.lower()
        if name.startswith("Install macOS"):
            add_path("storage", p, name, "macOS installer", "safe",
                     "Full macOS installer (12+ GB). Not needed after upgrading; re-download from the App Store or `softwareupdate --fetch-full-installer`.",
                     size=a["size"])
            continue
        try:
            sip = bool(os.lstat(p).st_flags & SF_RESTRICTED)
        except (OSError, AttributeError):
            sip = False
        mas = os.path.exists(os.path.join(p, "Contents/_MASReceipt"))
        running = p in RUNNING_APPS
        unused = days_ago(a["last_used"])
        category, safety, note = "Third-party app", "review", ""
        hay = (name + " " + bid).lower()
        for rx, cat, saf, n in BLOAT_APPS:
            if re.search(rx, hay):
                category, safety, note = cat, saf, n
                break
        if bl.startswith("com.apple."):
            if sip or bl == "com.apple.safari":
                category, safety, note = "Apple (system)", "protected", "Part of macOS (protected by System Integrity Protection)."
            else:
                category, safety = "Apple (optional)", "review"
                note = APPLE_OPTIONAL.get(bl, "Apple app installed from the App Store; can be reinstalled.")
        elif sip:
            category, safety = "Protected", "protected"
        sup = [] if safety == "protected" else support_paths(bid, name)
        sup_sizes = sizes(sup) if sup else {}
        sup_total = sum(sup_sizes.values())
        flags = []
        if running:
            flags.append("Running")
        if unused is None:
            flags.append("No usage recorded")
        elif unused > 180:
            flags.append("Unused %d days" % unused)
        if mas:
            flags.append("App Store")
        impact = "Removes %s. " % name
        if mas:
            impact += "Reinstall any time from the App Store (Purchased). "
        elif category == "Third-party app":
            impact += "Reinstall from the vendor's website if needed. "
        if note:
            impact += note + " "
        if sup:
            impact += ("Its settings/data (%s in %d places) stay unless you tick 'Also remove app support files' - "
                       "those can contain the app's own data (notes, libraries, chat history), so check before removing them. " % (human(sup_total), len(sup)))
        if running:
            impact += "It is running now and will be asked to quit first."
        if safety == "review" and category == "Third-party app" and unused is not None and unused > 365:
            safety = "safe"
            impact += " Not opened for over a year."
        add_item("apps", name, kind="app", path=p, size=a["size"], safety=safety, category=category,
                 impact=impact.strip(), note=" · ".join(flags),
                 action="Uninstall" if safety != "protected" else None,
                 meta=dict(version=a["version"], bid=bid, last_used=a["last_used"], unused_days=unused,
                           support_size=sup_total, support=sup, running=running),
                 export="mv %s ~/.Trash/" % q(p),
                 priv=dict(support=sup, bid=bid))


# ============================================================================ STORAGE / CACHES
def scan_storage(min_b):
    _du_done.wait()
    # Per-app caches in ~/Library/Caches
    for d in listdir(CACHES):
        p = os.path.join(CACHES, d)
        if not os.path.isdir(p) or os.path.islink(p):
            continue
        if d in DEV_CACHES:
            if DEV_CACHES[d] is None:
                continue
            label, imp = DEV_CACHES[d]
            add_path("dev", p, label, "Developer cache", "safe", imp + " Rebuilt automatically.", min_bytes=min_b)
            continue
        pretty = BID_TO_NAME.get(d.lower(), d)
        if d.startswith("com.apple.") or d in ("CloudKit", "GeoServices", "FamilyCircle", "com.crashlytics"):
            add_path("storage", p, "%s cache" % pretty, "macOS cache", "review",
                     "macOS component cache. Rebuilt automatically, but the related service (iCloud, Maps, Siri, etc.) may re-download data. Usually not worth clearing unless very large.",
                     min_bytes=min_b)
        elif d.endswith(".ShipIt") or "updater" in d.lower():
            add_path("storage", p, "%s (update downloads)" % pretty, "Updater cache", "safe",
                     "Leftover downloaded app updates. Safe to remove; the app re-downloads updates when needed.", min_bytes=min_b)
        else:
            add_path("storage", p, "%s cache" % pretty, "App cache", "safe",
                     "Cache for %s. The app rebuilds it as needed (may be a bit slower the first time). Quit the app before clearing." % pretty,
                     min_bytes=min_b)
    # Sandboxed app caches
    cache_dirs = [os.path.join(CONTAINERS, d, "Data/Library/Caches") for d in listdir(CONTAINERS)]
    cache_dirs = [c for c in cache_dirs if os.path.isdir(c)]
    for c, sz in sizes(cache_dirs).items():
        bid = c[len(CONTAINERS) + 1:].split("/")[0]
        pretty = BID_TO_NAME.get(bid.lower(), bid)
        apple = bid.startswith("com.apple.")
        add_path("storage", c, "%s cache (sandboxed)" % pretty, "macOS cache" if apple else "App cache",
                 "review" if apple else "safe",
                 ("Cache of a built-in Apple app/service; rebuilt automatically." if apple else
                  "Cache for %s. Rebuilt automatically; quit the app first." % pretty),
                 contents_only=True, size=sz, min_bytes=min_b)
    # Electron / Chromium caches inside Application Support
    names = ("Cache", "Code Cache", "GPUCache", "CachedData", "CachedExtensionVSIXs", "DawnCache",
             "Service Worker/CacheStorage", "Crashpad/completed", "ShaderCache", "logs")
    cands = []
    for depth in ("*", "*/*", "*/*/*"):
        for n in names:
            cands += glob.glob(os.path.join(glob.escape(AS), depth, n))
    cands = [c for c in set(cands) if os.path.isdir(c) and not os.path.islink(c)]
    for c, sz in sizes(cands).items():
        rel = c[len(AS) + 1:]
        app = rel.split("/")[0]
        kind = os.path.basename(c) if "Service Worker" not in c else "Service Worker cache"
        sw = "Service Worker" in c
        add_path("storage", c, "%s - %s" % (app, kind), "App cache", "review" if sw else "safe",
                 ("Offline storage of websites/web-apps used in %s. Rebuilt on demand; some web apps re-download their offline data." % app) if sw else
                 ("Browser/Electron cache for %s. Rebuilt automatically. Quit %s first." % (app, app)),
                 contents_only=True, size=sz, min_bytes=min_b)
    # Logs & crash reports
    add_path("storage", os.path.join(LIB, "Logs"), "User logs & crash reports", "Logs", "safe",
             "Old log files and crash reports. Only needed when troubleshooting.", contents_only=True, min_bytes=min_b)
    add_path("storage", os.path.join(AS, "CrashReporter"), "Crash reporter data", "Logs", "safe",
             "Crash-report bookkeeping. Re-created automatically.", contents_only=True, min_bytes=min_b)
    # Mail downloads / Messages
    add_path("storage", os.path.join(CONTAINERS, "com.apple.mail/Data/Library/Mail Downloads"), "Mail attachment downloads",
             "Mail", "safe", "Copies of attachments you opened from Mail. The originals stay in your mailbox.",
             contents_only=True, min_bytes=min_b)
    add_path("storage", os.path.join(LIB, "Messages/Attachments"), "Messages attachments", "Messages", "info",
             "Photos/videos from iMessage. Deleting files here breaks the conversation history; instead use System Settings > General > Storage > Messages, or Messages > Settings > Keep messages.",
             info=True, min_bytes=min_b)
    # iOS backups & updates
    bdir = os.path.join(AS, "MobileSync/Backup")
    for d in listdir(bdir):
        p = os.path.join(bdir, d)
        info = read_plist(os.path.join(p, "Info.plist"))
        dev = info.get("Device Name") or info.get("Display Name") or d[:12]
        when = info.get("Last Backup Date")
        when_s = when.strftime("%Y-%m-%d") if hasattr(when, "strftime") else "unknown date"
        add_path("storage", p, "iPhone/iPad backup: %s (%s)" % (dev, when_s), "Device backup", "caution",
                 "Local backup of %s. If you delete it and don't use iCloud Backup, you can't restore the device from it. Keep at least your latest one." % dev,
                 min_bytes=min_b)
    for n in ("iPhone Software Updates", "iPad Software Updates", "iPod Software Updates"):
        add_path("storage", os.path.join(LIB, "iTunes", n), n, "Device firmware", "safe",
                 "Downloaded iOS/iPadOS firmware files. Re-downloaded by Finder when needed.", contents_only=True, min_bytes=min_b)
    # Trash
    tsz = size_of(os.path.join(HOME, ".Trash"))
    add_cmd("storage", "Empty the Trash", ["osascript", "-e", 'tell application "Finder" to empty trash'], "Trash", "review",
            "Permanently deletes everything already in the Trash (including items moved there by this tool earlier). Not recoverable.",
            size=tsz, order=-10, note="" if tsz else "size unknown without Full Disk Access")
    # System-wide (admin) caches & optional content
    for d in listdir("/Library/Caches"):
        if d.startswith("com.apple") or d in ("ColorSync",):
            continue
        add_path("storage", os.path.join("/Library/Caches", d), "%s (system-wide cache)" % d, "App cache", "review",
                 "Cache shared by all users, owned by an installer/daemon. Usually safe to clear; you'll be asked for your password.",
                 min_bytes=min_b)
    for p, label, imp in (
        ("/Library/Application Support/GarageBand", "GarageBand sound library", "GarageBand/Logic instruments. Without them those apps offer to re-download sounds. Safe if you don't use GarageBand/Logic."),
        ("/Library/Application Support/Logic", "Logic sound library", "Logic Pro / GarageBand content. Re-downloadable from inside Logic."),
        ("/Library/Audio/Apple Loops", "Apple Loops", "Audio loops for GarageBand/Logic. Re-downloadable from inside those apps."),
    ):
        add_path("storage", p, label, "Optional content", "review", imp + " Asks for your password.", min_bytes=min_b)
    # Time Machine local snapshots
    rc, out, _ = sh(["tmutil", "listlocalsnapshots", "/"], timeout=20)
    snaps = [l for l in out.splitlines() if "com.apple.TimeMachine" in l]
    if snaps:
        add_cmd("storage", "Delete %d local Time Machine snapshot(s)" % len(snaps), ["tmutil", "deletelocalsnapshots", "/"],
                "Snapshots", "review",
                "Local snapshots let you restore recent versions while your backup disk is away. macOS deletes them by itself when space is needed (they count as 'purgeable'). Deleting frees that space now. Asks for your password.",
                admin=True, note="size not measurable; shown as purgeable in Finder")


# ============================================================================ DEVELOPER & AI
def scan_dev(min_b):
    _du_done.wait()
    dv = os.path.join(LIB, "Developer")
    X = os.path.join(dv, "Xcode")
    add_path("dev", os.path.join(X, "DerivedData"), "Xcode DerivedData", "Xcode", "safe",
             "Intermediate build products & indexes. Xcode rebuilds them (next build is slower).", contents_only=True, min_bytes=min_b)
    add_path("dev", os.path.join(X, "Archives"), "Xcode Archives", "Xcode", "caution",
             "Builds you archived for App Store/TestFlight. Needed to symbolicate crash reports of those releases.", min_bytes=min_b)
    for n in ("iOS DeviceSupport", "watchOS DeviceSupport", "tvOS DeviceSupport", "visionOS DeviceSupport"):
        add_path("dev", os.path.join(X, n), "Xcode %s" % n, "Xcode", "safe",
                 "Debug symbols copied from devices you connected. Re-copied when you connect that device again.", contents_only=True, min_bytes=min_b)
    add_path("dev", os.path.join(X, "iOS Device Logs"), "Xcode device logs", "Xcode", "safe", "Old device logs.", min_bytes=min_b)
    add_path("dev", os.path.join(dv, "CoreSimulator/Caches"), "Simulator caches", "Xcode", "safe", "Rebuilt automatically.", contents_only=True, min_bytes=min_b)
    simdev = os.path.join(dv, "CoreSimulator/Devices")
    if os.path.isdir(simdev) and have("xcrun"):
        add_cmd("dev", "Delete unavailable iOS simulators", ["xcrun", "simctl", "delete", "unavailable"], "Xcode", "safe",
                "Removes simulators for iOS versions no longer installed. Simulators you can still use are kept.",
                size=0, note="all simulators: %s" % human(size_of(simdev)))
    # Homebrew
    if have("brew"):
        rc, out, _ = sh(["brew", "--cache"], timeout=30)
        bc = out.strip()
        add_cmd("dev", "Homebrew: clean old versions & downloads", ["brew", "cleanup", "--prune=all", "-s"], "Homebrew", "safe",
                "Deletes cached downloads and outdated versions of installed formulae/casks. Installed tools keep working.",
                size=size_of(bc) if bc else 0, path=bc)
        add_cmd("dev", "Homebrew: remove unused dependencies", ["brew", "autoremove"], "Homebrew", "review",
                "Uninstalls formulae that were only installed as dependencies and are no longer needed by anything.")
        rc, out, _ = sh(["brew", "services", "list"], timeout=30)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("started", "scheduled"):
                add_cmd("background", "brew service: %s" % parts[0], ["brew", "services", "stop", parts[0]],
                        "Homebrew service", "review",
                        "Stops %s and keeps it from starting at login. Apps/projects that use it (e.g. a local database) can't connect until you run `brew services start %s`." % (parts[0], parts[0]))
    # Package-manager caches
    for p, label, imp in (
        (os.path.join(HOME, ".npm/_cacache"), "npm cache", "Packages re-download on next npm install."),
        (os.path.join(HOME, ".composer/cache"), "Composer cache (~/.composer)", "PHP packages re-download on next composer install."),
        (os.path.join(HOME, ".cache/composer"), "Composer cache (~/.cache)", "PHP packages re-download on next composer install."),
        (os.path.join(HOME, ".bun/install/cache"), "Bun cache", "Packages re-download on next bun install."),
        (os.path.join(HOME, ".gradle/caches"), "Gradle caches", "Dependencies re-download on next Gradle build."),
        (os.path.join(HOME, ".gradle/wrapper/dists"), "Gradle wrapper distributions", "Re-downloaded by ./gradlew."),
        (os.path.join(HOME, ".cache/pip"), "pip cache (~/.cache)", "Re-downloads on next pip install."),
        (os.path.join(HOME, ".cache/pre-commit"), "pre-commit environments", "Re-created on next commit."),
    ):
        add_path("dev", p, label, "Developer cache", "safe", imp, contents_only=True, min_bytes=min_b)
    for p, label, imp in (
        (os.path.join(HOME, ".m2/repository"), "Maven repository", "All Maven dependencies; re-downloaded on next build."),
        (os.path.join(HOME, ".cargo/registry"), "Cargo registry", "Rust crates; re-downloaded on next build."),
        (os.path.join(HOME, "go/pkg/mod"), "Go module cache", "Go modules; re-downloaded on next build (files are read-only, may need password)."),
        (os.path.join(HOME, ".android/avd"), "Android emulators (AVDs)", "Your Android virtual devices and their data."),
    ):
        add_path("dev", p, label, "Developer cache", "review", imp, contents_only=True, min_bytes=min_b)
    if os.path.isdir(os.path.join(LIB, "pnpm/store")) and have("pnpm"):
        add_cmd("dev", "pnpm: prune store", ["pnpm", "store", "prune"], "Developer cache", "safe",
                "Removes packages not referenced by any project.", size=size_of(os.path.join(LIB, "pnpm/store")))
    for conda in ("miniconda3", "anaconda3", "miniforge3"):
        if os.path.isdir(os.path.join(HOME, conda, "pkgs")):
            add_cmd("dev", "%s: clean package cache" % conda, [os.path.join(HOME, conda, "bin/conda"), "clean", "-a", "-y"],
                    "Developer cache", "safe", "Removes cached package tarballs and unused packages.",
                    size=size_of(os.path.join(HOME, conda, "pkgs")))
    for d in listdir(os.path.join(HOME, ".cache")):
        if d in ("huggingface", "lm-studio", "composer", "pip", "pre-commit"):
            continue
        add_path("dev", os.path.join(HOME, ".cache", d), "~/.cache/%s" % d, "Tool cache", "review",
                 "Cache for the '%s' command-line tool. Usually rebuilt automatically." % d, min_bytes=min_b)
    # Docker
    raw = glob.glob(os.path.join(CONTAINERS, "com.docker.docker/Data/vms/*/data/Docker.raw"))
    dsize = sum(size_of(r) for r in raw)
    if raw:
        add_path("dev", raw[0], "Docker Desktop disk image", "Docker", "info",
                 "Holds all Docker images, containers and volumes. Never delete this file directly; use the prune actions below, or lower the disk limit in Docker Desktop > Settings > Resources.",
                 size=dsize, info=True)
    if have("docker") and sh(["docker", "info"], timeout=15)[0] == 0:
        rc, out, _ = sh(["docker", "system", "df"], timeout=60)
        add_cmd("dev", "Docker: remove build cache", ["docker", "builder", "prune", "-af"], "Docker", "safe",
                "Deletes the image build cache. Next builds take longer.", meta=dict(df=out))
        add_cmd("dev", "Docker: remove unused images, stopped containers, networks", ["docker", "system", "prune", "-af"], "Docker", "review",
                "Removes stopped containers and every image not used by a running container. Images re-download/re-build on next use. Named volumes (database data) are KEPT.",
                note=out.strip().replace("\n", " | ")[:300])
        add_cmd("dev", "Docker: remove unused volumes", ["docker", "volume", "prune", "-af"], "Docker", "caution",
                "Deletes volumes not attached to a container - this is where local databases (MySQL, SQL Server, Redis...) keep their data. Data is lost permanently.")
    # Ollama models
    if have("ollama"):
        rc, out, _ = sh(["ollama", "list"], timeout=20)
        for line in out.splitlines()[1:]:
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 3 and parts[0]:
                add_cmd("dev", "Ollama model: %s" % parts[0], ["ollama", "rm", parts[0]], "Local AI model", "review",
                        "Deletes this model from disk. `ollama pull %s` downloads it again. Shared layers used by other models are kept." % parts[0],
                        size=parse_size_str(parts[2]), note="modified %s" % parts[3] if len(parts) > 3 else "")
    # Hugging Face & LM Studio
    for p in glob.glob(os.path.join(HOME, ".cache/huggingface/hub/models--*")) + glob.glob(os.path.join(HOME, ".cache/huggingface/hub/datasets--*")):
        nm = os.path.basename(p).split("--", 1)[-1].replace("--", "/")
        add_path("dev", p, "Hugging Face: %s" % nm, "Local AI model", "review",
                 "Downloaded model/dataset files. Re-downloaded automatically the next time code loads it.", min_bytes=min_b)
    for base in (os.path.join(HOME, ".lmstudio/models"), os.path.join(HOME, ".cache/lm-studio/models")):
        for p in glob.glob(os.path.join(base, "*", "*")):
            if os.path.isdir(p):
                add_path("dev", p, "LM Studio: %s" % p[len(base) + 1:], "Local AI model", "review",
                         "Model weights. Re-download from LM Studio's Discover tab if needed.", min_bytes=min_b)


# ============================================================================ PROJECT DEPS
def scan_projects(min_b, budget=150):
    t_end = time.time() + budget
    found = []
    skip_top = {"Library", "Applications", "Pictures", "Music", "Movies", "Public"}
    base_depth = HOME.rstrip("/").count("/")
    for root, dirs, files in os.walk(HOME, topdown=True):
        if time.time() > t_end:
            SCAN_WARNINGS.append("Project-dependency scan stopped after %ds; some folders were not searched." % budget)
            break
        depth = root.count("/") - base_depth
        if depth == 0:
            dirs[:] = [d for d in dirs if d not in skip_top and not d.startswith(".")]
        fs = set(files)
        keep = []
        for d in dirs:
            p = os.path.join(root, d)
            kind = None
            if d == "node_modules":
                kind = ("node_modules", "npm install / yarn / pnpm install")
            elif d == "vendor" and "composer.json" in fs:
                kind = ("Composer vendor", "composer install")
            elif d in (".venv", "venv", "env") and os.path.exists(os.path.join(p, "pyvenv.cfg")):
                kind = ("Python virtualenv", "python -m venv %s && pip install -r requirements.txt" % d)
            elif d == ".next" and "package.json" in fs:
                kind = (".next build", "next build / next dev")
            elif d == "target" and "Cargo.toml" in fs:
                kind = ("Rust target", "cargo build")
            elif d == "Pods" and "Podfile" in fs:
                kind = ("CocoaPods", "pod install")
            if kind:
                found.append((p, root, kind))
                continue
            if d.startswith(".") or d.endswith((".app", ".photoslibrary", ".bundle", ".framework")) or d in (".git",) or depth >= 8:
                continue
            keep.append(d)
        dirs[:] = keep
    if not found:
        return
    szs = sizes([f[0] for f in found])
    for p, proj, (label, how) in found:
        try:
            age = days_ago(max(os.stat(os.path.join(proj, f)).st_mtime for f in os.listdir(proj)))
        except (OSError, ValueError):
            age = None
        safety = "safe" if (age is not None and age > 60) else "review"
        add_path("projects", p, "%s · %s" % (os.path.basename(proj), label), label, safety,
                 "Dependencies/build output of project '%s' (last touched %s). Re-create with `%s` when you work on it again."
                 % (os.path.basename(proj), ("%d days ago" % age) if age is not None else "unknown", how),
                 size=szs.get(p, 0), min_bytes=min_b, meta=dict(age=age))


# ============================================================================ FILES
FILE_KINDS = [
    ((".dmg", ".pkg", ".iso", ".mpkg"), "Installer / disk image", "safe", "Installer or disk image. Once the app is installed it is no longer needed."),
    ((".mov", ".mp4", ".mkv", ".avi", ".m4v", ".webm"), "Video", "review", "Video file. Make sure you have a copy (e.g. cloud/external drive) before removing."),
    ((".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".xz", ".bz2"), "Archive", "review", "Compressed archive. Often already extracted - check before removing."),
    ((".vmdk", ".vdi", ".qcow2", ".raw", ".pvm", ".utm", ".img", ".vhd", ".vhdx", ".hdd"), "VM disk", "caution", "Virtual-machine disk. Removing deletes that VM."),
    ((".gguf", ".safetensors", ".bin", ".pt", ".pth", ".onnx", ".ckpt", ".mlmodel"), "AI model weights", "review", "Model weights; can usually be re-downloaded."),
    ((".bak", ".sql", ".mdf", ".ldf", ".dump", ".bacpac"), "Database / backup", "caution", "Database file or dump. Make sure it is not your only copy."),
    ((".log",), "Log file", "safe", "Log file; only needed for troubleshooting."),
]


def file_kind(p):
    pl = p.lower()
    for exts, cat, safety, imp in FILE_KINDS:
        if pl.endswith(exts):
            return cat, safety, imp
    return "File", "review", "Personal file. Make sure you don't need it or have a backup."


def scan_files(min_b, large_b):
    dl = os.path.join(HOME, "Downloads")
    for n in listdir(dl):
        p = os.path.join(dl, n)
        if n.startswith("."):
            continue
        sz = size_of(p)
        if sz < max(min_b, 50 * MB):
            continue
        try:
            age = days_ago(os.lstat(p).st_mtime)
        except OSError:
            age = None
        cat, safety, imp = file_kind(p) if os.path.isfile(p) else ("Folder", "review", "Folder in Downloads.")
        if cat == "File" and age is not None and age > 90:
            imp = "Downloaded file untouched for %d days." % age
        add_path("files", p, n, "Downloads · " + cat, safety, imp, size=sz,
                 note=("%d days old" % age) if age is not None else "", meta=dict(age=age))
    if ARGS.quick:
        return
    rc, out, _ = sh(["mdfind", "-onlyin", HOME, "kMDItemFSSize >= %d" % large_b], timeout=90)
    paths = [l for l in out.splitlines() if l.strip()]
    if not paths:
        rc, out, _ = sh(["find", HOME, "-xdev", "-type", "f", "-size", "+%dk" % (large_b // 1024),
                         "-not", "-path", "%s/Library/*" % HOME, "-not", "-path", "*/.Trash/*"], timeout=180)
        paths = [l for l in out.splitlines() if l.strip()]
    for p in paths:
        if (p.startswith(LIB + "/") or ".app/" in p or ".photoslibrary" in p or ".musiclibrary" in p
                or "/node_modules/" in p or "/.Trash/" in p or "/.ollama/" in p or "/.cache/huggingface/" in p
                or "/.lmstudio/" in p or not os.path.isfile(p) or os.path.islink(p)):
            continue
        try:
            st = os.lstat(p)
        except OSError:
            continue
        real = st.st_blocks * 512
        if real < large_b * 0.5:   # iCloud placeholder / sparse
            continue
        cat, safety, imp = file_kind(p)
        add_path("files", p, os.path.basename(p), "Large file · " + cat, safety, imp, size=real,
                 note="modified %d days ago" % days_ago(st.st_mtime), meta=dict(age=days_ago(st.st_mtime)))


# ============================================================================ LEFTOVERS
BID_RX = re.compile(r"^[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.[A-Za-z0-9_.-]+$")


def scan_leftovers(min_b):
    _du_done.wait()
    vendors = set(INSTALLED_VENDORS)
    # also treat vendors of loaded launch agents & running apps as "installed"
    for p in RUNNING_APPS:
        b = str(read_plist(os.path.join(p, "Contents/Info.plist")).get("CFBundleIdentifier", ""))
        if b:
            vendors.add(vendor_of(b))
    dirs = [AS, CACHES, CONTAINERS, os.path.join(LIB, "HTTPStorages"), os.path.join(LIB, "WebKit"),
            os.path.join(LIB, "Saved Application State"), os.path.join(LIB, "Logs"), GROUPC]
    cands = []
    for d in dirs:
        for n in listdir(d):
            name = n
            if d == GROUPC:
                if not n.startswith("group."):
                    continue
                name = n[6:]
            name = re.sub(r"\.(savedState|binarycookies)$", "", name)
            if not BID_RX.match(name):
                continue
            low = name.lower()
            if low.startswith(("com.apple.", "apple.")) or vendor_of(low) in vendors or vendor_of(low) in ("com.apple",):
                continue
            cands.append((os.path.join(d, n), name))
    szs = sizes([c[0] for c in cands])
    for p, name in cands:
        add_path("leftovers", p, name, "Possible leftover (%s)" % os.path.basename(os.path.dirname(p)), "review",
                 "No installed app from vendor '%s' was found, so this looks like data left behind by an uninstalled app. "
                 "If you removed that app on purpose, it is safe to delete. Keep it if the app lives elsewhere (external drive, command-line tool, or you plan to reinstall and want its settings)." % vendor_of(name),
                 size=szs.get(p, 0), min_bytes=min_b)


# ============================================================================ BACKGROUND ITEMS
def scan_background():
    rc, out, _ = sh(["launchctl", "list"])
    loaded = {}
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) == 3:
            loaded[parts[2]] = parts[0]
    snap = ps_snapshot()
    for d, where, admin in ((os.path.join(LIB, "LaunchAgents"), "Runs at your login (user agent)", False),
                            ("/Library/LaunchAgents", "Runs at every user's login (all-users agent)", True),
                            ("/Library/LaunchDaemons", "Runs at boot as root (system daemon)", True)):
        for plist in sorted(glob.glob(os.path.join(d, "*.plist"))):
            data = read_plist(plist)
            label = str(data.get("Label") or os.path.basename(plist)[:-6])
            args = data.get("ProgramArguments") or []
            prog = str(data.get("Program") or (args[0] if args else ""))
            cls = classify_agent(label, prog)
            broken = bool(prog) and prog.startswith("/") and not os.path.exists(prog)
            vendor, what, safety, impact = cls if cls else ("Unknown", "Third-party background item", "review",
                                                             "Starts '%s' automatically. Removing it stops that from running in the background; the owning app may lose features like auto-update, sync or its menu-bar helper, and may re-add it when launched." % (os.path.basename(prog) or label))
            if broken and safety != "protected":
                safety, what = "safe", "Broken leftover"
                impact = "The program it launches (%s) no longer exists - this is left over from an uninstalled app and does nothing useful." % prog
            elif safety == "review" and cls is None:
                owner = app_bundle_of(prog + "/") if ".app/" in prog else None
                vend = vendor_of(label)
                if not owner and vend not in INSTALLED_VENDORS and not label.startswith("homebrew"):
                    impact += " No installed app from '%s' was found - possibly a leftover." % vend
            pid = loaded.get(label)
            running = bool(pid and pid not in ("-", "0") and pid.isdigit())
            mem = snap.get(int(pid), {}).get("rss", 0) if running else 0
            notes = [where]
            notes.append("running (pid %s, %s)" % (pid, human(mem)) if running else ("loaded" if label in loaded else "not loaded / unknown"))
            if data.get("RunAtLoad"):
                notes.append("RunAtLoad")
            if data.get("KeepAlive"):
                notes.append("KeepAlive")
            extra = [prog] if (prog.startswith("/Library/PrivilegedHelperTools/") and safety != "protected") else []
            add_item("background", "%s - %s" % (vendor if vendor != "Unknown" else label, what), kind="launchd", path=plist,
                     size=mem, safety=safety, category="Launch %s" % ("daemon" if "Daemons" in d else "agent"),
                     impact=impact + (" Asks for your password." if admin and safety != "protected" else ""),
                     note=" · ".join(notes), action="Disable & remove" if safety != "protected" else None,
                     meta=dict(label=label, program=prog, running=running),
                     export=("sudo launchctl bootout system/%s; sudo mv %s ~/.Trash/" if admin else "launchctl bootout gui/$(id -u)/%s; mv %s ~/.Trash/") % (q(label), q(plist)),
                     priv=dict(label=label, admin=admin, daemon="Daemons" in d, extra=extra))
    # Login items (System Events). May trigger a one-time automation permission prompt.
    if ARGS.no_login_items:
        return
    scr = ('tell application "System Events"\nset out to ""\nrepeat with li in login items\n'
           'set out to out & (name of li) & tab & (path of li) & linefeed\nend repeat\nend tell\nreturn out')
    rc, out, err = sh(["osascript", "-e", scr], timeout=20)
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, p = line.split("\t", 1)
        cls = classify_agent(name, p)
        safety, impact = ("review", "%s stops opening automatically when you log in. You can still open it yourself." % name)
        if cls and cls[3] in ("caution", "protected", "safe"):
            safety, impact = cls[3], cls[4]
        add_item("background", "Login item: %s" % name, kind="loginitem", path=p, safety=safety, category="Login item",
                 impact=impact, action="Remove from login" if safety != "protected" else None,
                 export="osascript -e 'tell application \"System Events\" to delete login item \"%s\"'" % name.replace('"', ''),
                 priv=dict(name=name))


# ============================================================================ SPACE MAP
SPACE = {}


def scan_space(min_b):
    _du_done.wait()
    home_total = DU_MAP.get(HOME) or size_of(HOME)
    SPACE["home"] = home_total
    SPACE["apps"] = sum(a.get("size", 0) for a in APPS)
    used = SYS["disk"]["used"]
    SPACE["other"] = max(0, used - home_total - SPACE["apps"])
    SPACE["used"] = used

    def add_children(parent, prefix, limit):
        kids = []
        for n in listdir(parent):
            p = os.path.join(parent, n)
            if os.path.islink(p):
                continue
            kids.append((DU_MAP.get(p) if p in DU_MAP else 0, n, p))
        kids.sort(reverse=True)
        for sz, n, p in kids[:limit]:
            if sz < min_b:
                continue
            rel = p[len(HOME) + 1:]
            add_item("space", ("~/" + rel), kind="info", path=p, size=sz, safety="info", category=prefix,
                     impact=SPACE_INFO.get(rel, SPACE_INFO.get(n, "")))
    add_children(HOME, "Home folder", 30)
    add_children(LIB, "~/Library", 20)
    add_children(AS, "Application Support", 20)
    add_children(CONTAINERS, "Containers", 15)
    add_children(GROUPC, "Group Containers", 10)


# ============================================================================ RECOMMENDATIONS
def build_recs():
    recs = []
    by = lambda sec, s=None: [i for i in ITEMS.values() if i["section"] == sec and (s is None or i["safety"] == s)]
    disk_items = [i for i in ITEMS.values() if i["section"] not in ("processes", "space", "background") and i["deletable"]]
    safe = sum(i["size"] for i in disk_items if i["safety"] == "safe")
    review = sum(i["size"] for i in disk_items if i["safety"] == "review")
    d = SYS["disk"]
    free_pct = d["free"] * 100.0 / d["total"] if d["total"] else 100
    if free_pct < 10:
        recs.append(("warn", "Disk is %.0f%% full (%s free). macOS needs ~10-15%% free for swap, updates and snapshots." % (100 - free_pct, human(d["free"]))))
    recs.append(("good", "About %s can be reclaimed from items marked Safe, and %s more from items marked Review." % (human(safe), human(review))))
    mem = SYS.get("memory", {})
    if mem.get("swap_used", 0) > 2 * GB or (mem.get("free_pct") is not None and mem["free_pct"] < 20):
        top = ", ".join("%s (%s)" % (n, human(s)) for n, s in PROC_SUMMARY.get("top_mem", [])[:4])
        recs.append(("warn", "Memory is under pressure (swap used %s, %s%% free). Biggest users: %s." % (human(mem.get("swap_used", 0)), mem.get("free_pct", "?"), top)))
    hot = [(n, c) for n, c in PROC_SUMMARY.get("top_cpu", []) if c >= 50]
    if hot:
        recs.append(("warn", "High CPU right now: " + ", ".join("%s %.0f%%" % (n, c) for n, c in hot) + " (100% = one full core). See CPU & Memory."))
    names = " ".join(n.lower() for n, _ in PROC_SUMMARY.get("top_cpu", []))
    if re.search(r"mds|mdworker|spotlight", names):
        recs.append(("info", "Spotlight is indexing. Exclude node_modules/vendor/Docker/model folders in System Settings > Spotlight > Search Privacy to keep it quiet."))
    if any("docker" in n.lower() or "virtualization" in n.lower() for n, _ in PROC_SUMMARY.get("top_mem", [])):
        recs.append(("info", "Docker's VM is one of the largest memory users. Cap it in Docker Desktop > Settings > Resources or quit Docker when idle."))
    adware = [i["name"] for i in ITEMS.values() if i["category"] in ("Adware / PUP",) or (i["section"] == "background" and "Adware" in i["name"])]
    if adware:
        recs.append(("warn", "Adware / unwanted software found: %s. Remove it from Applications and Background items." % ", ".join(sorted(set(adware))[:5])))
    broken = [i for i in by("background") if "Broken" in i["name"]]
    if broken:
        recs.append(("info", "%d background item(s) point to programs that no longer exist - safe to remove." % len(broken)))
    unused = [i for i in by("apps") if (i["meta"].get("unused_days") or 0) > 180 and i["deletable"]]
    if unused:
        recs.append(("info", "%d apps haven't been opened in 6+ months (%s)." % (len(unused), human(sum(i["size"] + i["meta"].get("support_size", 0) for i in unused)))))
    if SYS.get("uptime_days") and SYS["uptime_days"] > 14:
        recs.append(("info", "Mac has been up for %.0f days. A restart clears swap files and stuck background processes." % SYS["uptime_days"]))
    if SPACE.get("other", 0) > 40 * GB:
        recs.append(("info", "%s is outside your home folder and /Applications ('System Data'): macOS itself, swap, Time Machine snapshots, other users and system caches. Most of it is managed by macOS." % human(SPACE["other"])))
    return [dict(level=l, text=t) for l, t in recs]


# ============================================================================ ACTIONS
_TRASH_SESSION = None


def trash_session_dir():
    global _TRASH_SESSION
    if _TRASH_SESSION is None:
        d = os.path.join(HOME, ".Trash", "Mac Cleanup " + dt.datetime.now().strftime("%Y-%m-%d %H.%M.%S"))
        try:
            os.makedirs(d)
            _TRASH_SESSION = d
        except OSError:
            _TRASH_SESSION = ""   # Trash not writable (no Full Disk Access) -> use Finder
    return _TRASH_SESSION


def unique_dest(base, name):
    dest = os.path.join(base, name)
    i = 2
    while os.path.lexists(dest):
        dest = os.path.join(base, "%s %d" % (name, i))
        i += 1
    return dest


def record_restore(orig, dest):
    try:
        with open(os.path.join(trash_session_dir() or REPORT_DIR, "RESTORE.txt"), "a") as f:
            f.write("%s\t<-\t%s\n" % (os.path.relpath(dest, trash_session_dir() or "/"), orig))
    except OSError:
        pass


def finder_trash(p):
    rc, out, err = sh(["osascript", "-e", "on run argv", "-e",
                       'tell application "Finder" to delete ((POSIX file (item 1 of argv)) as alias)',
                       "-e", "end run", p], timeout=180)
    return rc == 0, err.strip()


def remove_path(p, mode, admin_q, iid, dest_dir=None):
    """Returns (state, message); state is ok | admin | fail."""
    p = os.path.normpath(p)
    if not path_is_safe(p):
        return "fail", "refused: protected location %s" % p
    if not os.path.lexists(p):
        return "ok", "already gone"
    try:
        owner = os.lstat(p).st_uid
    except OSError:
        owner = UID
    if mode == "trash":
        base = dest_dir or trash_session_dir()
        if base:
            dest = unique_dest(base, os.path.basename(p))
            try:
                os.rename(p, dest)
                record_restore(p, dest)
                return "ok", "moved to Trash"
            except OSError as e:
                if e.errno == errno.EXDEV:
                    try:
                        shutil.move(p, dest)
                        record_restore(p, dest)
                        return "ok", "moved to Trash"
                    except OSError:
                        pass
                elif e.errno in (errno.EACCES, errno.EPERM) and owner != UID:
                    admin_q.append((iid, "mv -f %s %s" % (q(p), q(dest))))
                    record_restore(p, dest)
                    return "admin", ""
        ok, err = finder_trash(p)
        if ok:
            return "ok", "moved to Trash (Finder)"
        if owner != UID:
            admin_q.append((iid, "rm -rf %s" % q(p)))
            return "admin", "Finder failed; deleting with admin rights"
        return "fail", "could not move to Trash: %s (grant Full Disk Access to your terminal?)" % (err or "permission denied")
    # permanent
    try:
        if os.path.islink(p) or not os.path.isdir(p):
            os.unlink(p)
        else:
            shutil.rmtree(p)
        return "ok", "deleted"
    except OSError as e:
        if owner != UID or e.errno in (errno.EACCES,):
            admin_q.append((iid, "rm -rf %s" % q(p)))
            return "admin", ""
        return "fail", "could not delete: %s (grant Full Disk Access to your terminal?)" % e


def clear_contents(d, mode, admin_q, iid):
    if not os.path.isdir(d):
        return "ok", "already empty"
    try:
        kids = os.listdir(d)
    except OSError as e:
        return "fail", "cannot read folder: %s" % e
    dest_dir = None
    if mode == "trash" and trash_session_dir():
        dest_dir = unique_dest(trash_session_dir(), os.path.basename(d))
        try:
            os.makedirs(dest_dir)
        except OSError:
            dest_dir = None
    states = [remove_path(os.path.join(d, k), mode, admin_q, iid, dest_dir=dest_dir) for k in kids]
    return combine(states, "cleared %d entries" % len(kids))


def combine(states, okmsg=None):
    fails = [m for s, m in states if s == "fail"]
    if fails:
        return "fail", "%d of %d failed: %s" % (len(fails), len(states), fails[0])
    if any(s == "admin" for s, _ in states):
        return "admin", okmsg or ""
    return "ok", okmsg or (states[0][1] if states else "nothing to do")


def app_quit(bid):
    if bid and re.match(r"^[\w.-]+$", bid):
        sh(["osascript", "-e", 'tell application id "%s" to quit' % bid], timeout=20)
        time.sleep(2)


def exec_item(iid, mode, dry, include_support, admin_q):
    it, pv = ITEMS[iid], PRIV[iid]
    kind = it["kind"]
    verb = "move to Trash" if mode == "trash" else "permanently delete"
    if kind == "path":
        paths = pv.get("paths", [it["path"]])
        if dry:
            return "ok", "Would %s%s: %s" % ("clear the contents of " if pv.get("contents_only") else "", "" if pv.get("contents_only") else verb, ", ".join(paths))
        fn = clear_contents if pv.get("contents_only") else remove_path
        return combine([fn(p, mode, admin_q, iid) for p in paths])
    if kind == "app":
        paths = [it["path"]] + (pv.get("support", []) if include_support else [])
        if dry:
            return "ok", "Would %s %d item(s): %s" % (verb, len(paths), "; ".join(paths))
        if it["path"] in RUNNING_APPS:
            app_quit(pv.get("bid"))
        states = []
        for p in paths:
            if "/LaunchAgents/" in p:
                lab = str(read_plist(p).get("Label", ""))
                if lab:
                    sh(["launchctl", "bootout", "gui/%d/%s" % (UID, lab)])
            states.append(remove_path(p, mode, admin_q, iid))
        return combine(states, "uninstalled")
    if kind == "command":
        if dry:
            return "ok", "Would run: %s" % it["export"]
        if pv.get("admin"):
            admin_q.append((iid, " ".join(q(c) for c in pv["cmd"])))
            return "admin", ""
        rc, out, err = sh(pv["cmd"], timeout=pv.get("timeout", 900))
        tail = (out + "\n" + err).strip()[-300:]
        return ("ok" if rc == 0 else "fail"), (tail or "exit code %d" % rc)
    if kind == "launchd":
        label = pv["label"]
        if dry:
            return "ok", "Would stop %s and %s %s" % (label, verb, it["path"])
        if pv.get("admin"):
            admin_q.append((iid, "launchctl bootout system/%s 2>/dev/null; launchctl bootout gui/%d/%s 2>/dev/null; true" % (q(label), UID, q(label))))
        else:
            sh(["launchctl", "bootout", "gui/%d/%s" % (UID, label)])
        states = [remove_path(p, mode, admin_q, iid) for p in [it["path"]] + pv.get("extra", [])]
        st, msg = combine(states, "stopped and removed")
        if st == "ok" and pv.get("admin"):
            st = "admin"
        return st, msg
    if kind == "loginitem":
        if dry:
            return "ok", "Would remove login item %s" % pv["name"]
        rc, out, err = sh(["osascript", "-e", "on run argv", "-e",
                           'tell application "System Events" to delete login item (item 1 of argv)', "-e", "end run", pv["name"]], timeout=20)
        return ("ok", "removed from login items") if rc == 0 else ("fail", err.strip())
    if kind == "process":
        if dry:
            return "ok", "Would %s %s (%d processes)" % ("quit" if pv.get("bid") else "terminate", it["name"], len(pv["pids"]))
        cur = ps_snapshot()
        live = [pid for pid, comm in pv["pids"] if pid in cur and cur[pid]["comm"] == comm]
        if not live:
            return "ok", "not running anymore"
        pv["tries"] = pv.get("tries", 0) + 1
        if pv.get("bid") and pv["tries"] == 1:
            app_quit(pv["bid"])
            cur = ps_snapshot()
            still = [p for p in live if p in cur]
            if not still:
                return "ok", "quit"
            return "fail", "Still running - it may be asking to save documents. Switch to it, or run again to force-terminate."
        for pid in live:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        return "ok", "terminated"
    return "fail", "nothing to do"


def run_admin_batch(admin_q):
    lines = []
    for i, (iid, cmd) in enumerate(admin_q):
        lines.append("if { %s ; } >/dev/null 2>&1; then echo OK %d; else echo FAIL %d; fi" % (cmd, i, i))
    script = "\n".join(lines)
    rc, out, err = sh(["osascript", "-e", "on run argv", "-e",
                       "do shell script (item 1 of argv) with administrator privileges", "-e", "end run", script], timeout=1800)
    res = {int(n): s == "OK" for s, n in re.findall(r"(OK|FAIL) (\d+)", out)}
    return res, ("" if rc == 0 else (err.strip() or "administrator step failed"))


EXEC_LOCK = threading.Lock()


def execute(ids, mode, dry, include_support):
    mode = "delete" if mode == "delete" else "trash"
    with EXEC_LOCK:
        admin_q, out = [], {}
        order = sorted([i for i in ids if i in ITEMS], key=lambda i: PRIV[i].get("order", 0))
        for iid in ids:
            if iid not in ITEMS:
                out[iid] = ("fail", "unknown item")
        for iid in order:
            it = ITEMS[iid]
            if not it["deletable"]:
                out[iid] = ("fail", "protected - not allowed")
                continue
            if it.get("status") == "done":
                out[iid] = ("ok", "already done")
                continue
            try:
                out[iid] = exec_item(iid, mode, dry, include_support, admin_q)
            except Exception as e:
                out[iid] = ("fail", "error: %s" % e)
        if admin_q and not dry:
            res, err = run_admin_batch(admin_q)
            per = {}
            for idx, (iid, _) in enumerate(admin_q):
                per.setdefault(iid, []).append(res.get(idx, False))
            for iid, oks in per.items():
                st, msg = out.get(iid, ("admin", ""))
                if st == "fail":
                    continue
                out[iid] = ("ok", (msg + " " if msg else "") + "(with admin rights)") if all(oks) else \
                    ("fail", "admin step failed" + (": " + err if err else ""))
        results = []
        os.makedirs(REPORT_DIR, exist_ok=True)
        with open(os.path.join(REPORT_DIR, "actions.log"), "a") as lf:
            for iid in ids:
                st, msg = out.get(iid, ("fail", "?"))
                ok = st == "ok"
                if not dry and iid in ITEMS:
                    ITEMS[iid]["status"] = "done" if ok else "error"
                    ITEMS[iid]["status_msg"] = msg
                results.append(dict(id=iid, ok=ok, msg=msg))
                if not dry and iid in ITEMS:
                    lf.write(json.dumps(dict(time=dt.datetime.now().isoformat(timespec="seconds"), mode=mode, ok=ok,
                                             name=ITEMS[iid]["name"], path=ITEMS[iid]["path"], kind=ITEMS[iid]["kind"],
                                             msg=msg)) + "\n")
        return dict(results=results, trash_folder=_TRASH_SESSION or "")


# ============================================================================ REPORT / SERVER
TOKEN = secrets.token_urlsafe(24)
PORT = 0


def build_data(server):
    return dict(version=VERSION, generated=dt.datetime.now().strftime("%Y-%m-%d %H:%M"), server=server,
                token=TOKEN if server else "", host=SYS, space=SPACE, procs=PROC_SUMMARY,
                recs=build_recs(), warnings=[w for w in SCAN_WARNINGS if w], items=list(ITEMS.values()),
                home=HOME, user=ME)


def render_html(server):
    data = json.dumps(build_data(server), default=str).replace("</", "<\\/")
    return HTML_TEMPLATE.replace("__DATA__", data)


class Handler(BaseHTTPRequestHandler):
    server_version = "MacCleanup/" + VERSION

    def log_message(self, *a):
        pass

    def _host_ok(self):
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        allowed = ("127.0.0.1:%d" % PORT, "localhost:%d" % PORT)
        if host not in allowed:
            return False
        if origin and origin not in ("http://" + allowed[0], "http://" + allowed[1]):
            return False
        return True

    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if not self._host_ok():
            return self._send(403, "forbidden", "text/plain")
        if u.path == "/" and parse_qs(u.query).get("t", [""])[0] == TOKEN:
            return self._send(200, render_html(True), "text/html")
        return self._send(404, "not found (open the URL printed in the terminal)", "text/plain")

    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-Token") != TOKEN:
            return self._send(403, '{"error":"forbidden"}')
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, '{"error":"bad json"}')
        path = urlparse(self.path).path
        if path == "/api/execute":
            ids = [str(i) for i in body.get("ids", [])][:2000]
            res = execute(ids, body.get("mode", "trash"), bool(body.get("dry_run")), bool(body.get("include_support")))
            return self._send(200, json.dumps(res))
        if path == "/api/reveal":
            it = ITEMS.get(str(body.get("id")))
            if it and it["path"] and os.path.lexists(it["path"]):
                sh(["open", "-R", it["path"]], timeout=10)
                return self._send(200, '{"ok":true}')
            return self._send(404, '{"ok":false}')
        if path == "/api/shutdown":
            self._send(200, '{"ok":true}')
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        return self._send(404, '{"error":"unknown"}')


# ============================================================================ MAIN
def run_step(label, fn, *a):
    t = time.time()
    say("-> %s..." % label)
    try:
        fn(*a)
    except Exception as e:
        SCAN_WARNINGS.append("%s failed: %s" % (label, e))
        say("   ! %s failed: %s" % (label, e))
    say("   done in %.1fs" % (time.time() - t))


def main():
    global ARGS, PORT
    ap = argparse.ArgumentParser(description="Audit & clean up disk, memory and CPU usage on macOS.")
    ap.add_argument("--quick", action="store_true", help="skip project-dependency and large-file searches")
    ap.add_argument("--no-serve", action="store_true", help="write a static report only (no delete buttons)")
    ap.add_argument("--min-mb", type=int, default=25, help="hide items smaller than this (MB, default 25)")
    ap.add_argument("--large-mb", type=int, default=500, help="'large file' threshold in MB (default 500)")
    ap.add_argument("--port", type=int, default=0, help="port for the local report server (default: random)")
    ap.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    ap.add_argument("--no-login-items", action="store_true", help="skip reading Login Items (avoids an automation prompt)")
    ap.add_argument("--allow-non-mac", action="store_true", help=argparse.SUPPRESS)
    ARGS = ap.parse_args()
    if sys.platform != "darwin" and not ARGS.allow_non_mac:
        sys.exit("This script is for macOS.")
    if os.geteuid() == 0 and not ARGS.allow_non_mac:
        sys.exit("Please run as your normal user (not sudo). You'll be asked for your password only for items that need it.")
    min_b = ARGS.min_mb * MB
    t0 = time.time()
    say("Mac Cleanup %s - scanning (read-only). This takes 1-4 minutes.\n" % VERSION)
    du_thread = threading.Thread(target=du_home_tree, daemon=True)
    du_thread.start()
    run_step("System info", scan_system)
    run_step("Memory", scan_memory)
    run_step("Processes (sampling CPU for 2s)", scan_processes)
    run_step("Applications", scan_apps)
    say("-> Measuring your home folder in the background (largest step)...")
    run_step("Storage & caches", scan_storage, min_b)
    run_step("Developer tools & AI models", scan_dev, min_b)
    run_step("Background items (launch agents/daemons, login items)", scan_background)
    run_step("Leftovers from uninstalled apps", scan_leftovers, min_b)
    run_step("Downloads & large files", scan_files, min_b, ARGS.large_mb * MB)
    if not ARGS.quick:
        run_step("Project dependencies (node_modules, vendor, venv...)", scan_projects, min_b)
    run_step("Space map", scan_space, min_b)
    say("\nScan finished in %.0fs: %d items." % (time.time() - t0, len(ITEMS)))

    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    static_path = os.path.join(REPORT_DIR, "report-%s.html" % stamp)
    with open(static_path, "w") as f:
        f.write(render_html(False))
    say("Static report saved: %s" % static_path)

    if ARGS.no_serve:
        if not ARGS.no_browser:
            webbrowser.open("file://" + static_path)
        return
    srv = ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler)
    PORT = srv.server_address[1]
    url = "http://127.0.0.1:%d/?t=%s" % (PORT, TOKEN)
    say("\nInteractive report: %s\n(keep this terminal open; press Ctrl+C or use 'Finish' in the page to stop)\n" % url)
    if not ARGS.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    srv.server_close()
    if _TRASH_SESSION:
        say("Removed items are in the Trash folder: %s" % _TRASH_SESSION)
    say("Action log: %s" % os.path.join(REPORT_DIR, "actions.log"))


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mac Cleanup Report</title>
<style>
:root{--bg:#f5f6f8;--panel:#fff;--text:#1c1e22;--muted:#6b7280;--line:#e6e8ec;--accent:#2563eb;--accent-text:#fff;
--safe:#15803d;--safe-bg:#dcfce7;--review:#92400e;--review-bg:#fef3c7;--caution:#b91c1c;--caution-bg:#fee2e2;
--prot:#475569;--prot-bg:#e2e8f0;--bar:#3b82f6;--bar2:#a855f7;--bar3:#94a3b8;--row-hover:#f8fafc;--done:#9ca3af}
@media (prefers-color-scheme:dark){:root{--bg:#0e1014;--panel:#171a20;--text:#e6e7ea;--muted:#9aa1ad;--line:#272b33;--accent:#5b8def;
--safe:#4ade80;--safe-bg:#12301d;--review:#fbbf24;--review-bg:#3a2d0a;--caution:#f87171;--caution-bg:#3b1414;--prot:#cbd5e1;--prot-bg:#262d38;
--bar:#5b8def;--bar2:#c084fc;--bar3:#64748b;--row-hover:#1c2028;--done:#5b6270}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",sans-serif;padding-bottom:84px}
header{padding:20px 24px 8px;display:flex;flex-wrap:wrap;gap:8px 24px;align-items:baseline;justify-content:space-between}
h1{font-size:22px;margin:0;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px}
.wrap{padding:0 24px;max-width:1500px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin:12px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card h3{margin:0 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
.big{font-size:22px;font-weight:650;font-variant-numeric:tabular-nums}
.meter{height:8px;background:var(--line);border-radius:5px;overflow:hidden;margin:8px 0 6px;display:flex}
.meter span{display:block;height:100%}
.small{font-size:12px;color:var(--muted)}
.warnbox{background:var(--review-bg);color:var(--review);border-radius:10px;padding:10px 14px;margin:8px 0;font-size:13px}
nav.tabs{display:flex;gap:4px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin:16px 0 0;position:sticky;top:0;background:var(--bg);z-index:5;padding-top:6px}
nav.tabs button{border:0;background:none;color:var(--muted);padding:9px 12px;font:inherit;cursor:pointer;border-bottom:2px solid transparent;border-radius:6px 6px 0 0}
nav.tabs button.on{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
nav.tabs button .cnt{font-size:11px;color:var(--muted);margin-left:4px;font-variant-numeric:tabular-nums}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0}
.toolbar input[type=search]{flex:1;min-width:200px;max-width:380px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text);font:inherit}
.chip{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:999px;padding:5px 11px;font:inherit;font-size:12px;cursor:pointer}
.chip.on{background:var(--accent);color:var(--accent-text);border-color:var(--accent)}
.btn{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:8px;padding:7px 12px;font:inherit;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);color:var(--accent-text);border-color:var(--accent);font-weight:600}
.btn.danger{background:var(--caution);color:#fff;border-color:var(--caution);font-weight:600}
.btn:disabled{opacity:.45;cursor:not-allowed}
.tablewrap{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:900px}
th,td{padding:9px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
th{font-size:12px;color:var(--muted);font-weight:600;white-space:nowrap;cursor:pointer;user-select:none;position:sticky;top:0;background:var(--panel)}
tr:hover td{background:var(--row-hover)}
tr.done td{color:var(--done)}
tr.done .n{text-decoration:line-through}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.n{font-weight:600;word-break:break-word}
.p{font:11.5px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);word-break:break-all;margin-top:2px}
.impact{font-size:12.5px;max-width:520px}
.note{font-size:11.5px;color:var(--muted);margin-top:3px}
.badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;white-space:nowrap}
.b-safe{background:var(--safe-bg);color:var(--safe)}.b-review{background:var(--review-bg);color:var(--review)}
.b-caution{background:var(--caution-bg);color:var(--caution)}.b-protected,.b-info{background:var(--prot-bg);color:var(--prot)}
.tag{display:inline-block;font-size:10.5px;padding:1px 6px;border-radius:5px;background:var(--prot-bg);color:var(--prot);margin:2px 4px 0 0;font-weight:500}
.acts{white-space:nowrap}
.link{background:none;border:0;color:var(--accent);cursor:pointer;font:inherit;font-size:12px;padding:2px 4px}
.st-ok{color:var(--safe);font-size:12px}.st-err{color:var(--caution);font-size:12px}
input[type=checkbox]{width:16px;height:16px;accent-color:var(--accent);cursor:pointer}
.bar{position:fixed;left:0;right:0;bottom:0;background:var(--panel);border-top:1px solid var(--line);padding:12px 24px;display:flex;gap:14px;align-items:center;flex-wrap:wrap;z-index:10;box-shadow:0 -4px 18px rgba(0,0,0,.06)}
.bar .sel{font-weight:600;font-variant-numeric:tabular-nums}
.bar select{padding:6px 8px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--text);font:inherit}
.bar label{font-size:13px;display:flex;gap:6px;align-items:center}
.spacer{flex:1}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:900px){.grid2{grid-template-columns:1fr}}
.recs{list-style:none;padding:0;margin:0}
.recs li{padding:8px 0;border-bottom:1px solid var(--line);display:flex;gap:10px;font-size:13.5px}
.recs li:last-child{border-bottom:0}
.dot{width:8px;height:8px;border-radius:50%;margin-top:6px;flex:none}
.d-warn{background:var(--caution)}.d-good{background:var(--safe)}.d-info{background:var(--accent)}
.srow{display:grid;grid-template-columns:minmax(140px,240px) 1fr 80px;gap:10px;align-items:center;padding:5px 0;font-size:13px}
.srow .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.strack{height:10px;background:var(--line);border-radius:5px;overflow:hidden}
.strack span{display:block;height:100%;background:var(--bar);border-radius:5px}
.legend span{margin-right:12px}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:center;justify-content:center;z-index:50;padding:16px}
.modal{background:var(--panel);border-radius:14px;max-width:860px;width:100%;max-height:88vh;display:flex;flex-direction:column;border:1px solid var(--line)}
.modal header{padding:16px 20px;border-bottom:1px solid var(--line)}
.modal .body{padding:14px 20px;overflow:auto}
.modal footer{padding:12px 20px;border-top:1px solid var(--line);display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;align-items:center}
.mitem{padding:7px 0;border-bottom:1px solid var(--line);font-size:13px}
.mitem:last-child{border-bottom:0}
pre{background:var(--bg);padding:10px;border-radius:8px;overflow:auto;font-size:12px;max-height:50vh;white-space:pre-wrap}
.empty{padding:30px;text-align:center;color:var(--muted)}
.hint{font-size:12.5px;color:var(--muted);margin:6px 0 0}
</style>
</head>
<body>
<script id="data" type="application/json">__DATA__</script>
<header>
  <div><h1>Mac Cleanup Report</h1><div class="sub" id="subtitle"></div></div>
  <div class="small" id="modeinfo"></div>
</header>
<div class="wrap">
  <div id="warnings"></div>
  <div class="cards" id="cards"></div>
  <nav class="tabs" id="tabs"></nav>
  <div id="content"></div>
</div>
<div class="bar" id="bar">
  <span class="sel" id="selinfo">Nothing selected</span>
  <span class="spacer"></span>
  <label title="Applies to app uninstalls"><input type="checkbox" id="inclSupport"> Also remove app support files</label>
  <select id="mode"><option value="trash">Move to Trash (recoverable)</option><option value="delete">Delete permanently</option></select>
  <button class="btn" id="clearSel">Clear selection</button>
  <button class="btn primary" id="go" disabled>Review &amp; clean up…</button>
  <button class="btn" id="finish" title="Stop the local report server">Finish</button>
</div>
<div class="modal-bg" id="modalbg"><div class="modal"><header id="mh"></header><div class="body" id="mb"></div><footer id="mf"></footer></div></div>

<script>
const D = JSON.parse(document.getElementById('data').textContent);
const SERVER = D.server;
const BYID = {}; D.items.forEach(i => BYID[i.id] = i);
const SECTIONS = [
  ['overview','Overview'],['storage','Storage & caches'],['apps','Applications'],['dev','Developer & AI'],
  ['projects','Project deps'],['files','Large files & Downloads'],['leftovers','Leftovers'],
  ['background','Background items'],['processes','CPU & Memory']];
const SAFETY_LABEL = {safe:'Safe',review:'Review',caution:'Caution',protected:'Protected',info:'Info'};
const SAFETY_HELP = {
  safe:'Rebuilt automatically or clearly unneeded. Removing it does not break anything.',
  review:'Probably fine to remove, but depends on how you use it. Read the impact first.',
  caution:'Contains data or is needed by something important. Remove only if you are sure.',
  protected:'Part of macOS or managed by your organization. Cannot be removed here.'};
const state = {tab:'overview', sel:new Set(), q:'', safety:'all', sort:{key:'size',dir:-1}};

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function hb(n){n=+n||0;const u=['B','KB','MB','GB','TB'];let i=0;while(Math.abs(n)>=1024&&i<4){n/=1024;i++}return (i<2?n.toFixed(0):n.toFixed(1))+' '+u[i]}
const badge = s => `<span class="badge b-${s}" title="${esc(SAFETY_HELP[s]||'')}">${SAFETY_LABEL[s]||s}</span>`;
const isDisk = i => !['processes','space','background'].includes(i.section);
const itemsIn = sec => D.items.filter(i => i.section === sec);

function header(){
  const h = D.host;
  document.getElementById('subtitle').textContent =
    `${h.model||'Mac'} · ${h.cpu||''} · ${hb(h.mem_total)} RAM · ${h.macos||''} · scanned ${D.generated}`;
  document.getElementById('modeinfo').innerHTML = SERVER
    ? 'Live mode: actions run on this Mac. Default is <b>Move to Trash</b>.'
    : 'Static report: no actions run from here. Select items and export a shell script, or re-run the script without --no-serve.';
  document.getElementById('warnings').innerHTML = (D.warnings||[]).map(w=>`<div class="warnbox">${esc(w)}</div>`).join('');
  const d = h.disk||{}, m = h.memory||{}, sp = D.space||{};
  const usedPct = d.total ? d.used/d.total*100 : 0;
  const deletable = D.items.filter(i=>i.deletable && isDisk(i));
  const safe = deletable.filter(i=>i.safety==='safe').reduce((a,i)=>a+i.size,0);
  const review = deletable.filter(i=>i.safety==='review').reduce((a,i)=>a+i.size,0);
  const memPct = m.total ? (m.used/m.total*100) : 0;
  const pr = D.procs||{};
  const cores = h.cores||1;
  const cpuPct = Math.min(100,(pr.total_cpu_now||0)/cores);
  const topCpu = (pr.top_cpu||[]).slice(0,3).map(x=>`${esc(x[0])} ${x[1].toFixed(0)}%`).join(', ');
  const topMem = (pr.top_mem||[]).slice(0,3).map(x=>`${esc(x[0])} ${hb(x[1])}`).join(', ');
  const seg = (v,t,c)=> t? `<span style="width:${(v/t*100).toFixed(2)}%;background:${c}"></span>`:'';
  document.getElementById('cards').innerHTML = `
  <div class="card"><h3>Disk</h3><div class="big">${hb(d.free)} free</div>
    <div class="meter">${seg(sp.home||0,d.total,'var(--bar)')}${seg(sp.apps||0,d.total,'var(--bar2)')}${seg(sp.other||0,d.total,'var(--bar3)')}</div>
    <div class="small legend"><span style="color:var(--bar)">■</span> Home ${hb(sp.home)} <span style="color:var(--bar2)">■</span> Apps ${hb(sp.apps)} <span style="color:var(--bar3)">■</span> System &amp; other ${hb(sp.other)}</div>
    <div class="small">${usedPct.toFixed(0)}% of ${hb(d.total)} used</div></div>
  <div class="card"><h3>Reclaimable space</h3><div class="big">${hb(safe)}</div>
    <div class="small">marked <b>Safe</b> · plus ${hb(review)} marked <b>Review</b></div>
    <div class="hint">Use "Select all Safe" in each tab to start.</div></div>
  <div class="card"><h3>Memory</h3><div class="big">${hb(m.used)} <span class="small">of ${hb(m.total)}</span></div>
    <div class="meter">${seg(m.app||0,m.total,'var(--bar)')}${seg(m.wired||0,m.total,'var(--bar2)')}${seg(m.compressed||0,m.total,'var(--caution)')}</div>
    <div class="small">App ${hb(m.app)} · Wired ${hb(m.wired)} · Compressed ${hb(m.compressed)} · Cached files ${hb(m.cached)}</div>
    <div class="small">Swap used ${hb(m.swap_used)}${m.free_pct!=null?` · pressure: ${m.free_pct}% free`:''}</div>
    <div class="small">Top: ${topMem||'-'}</div></div>
  <div class="card"><h3>CPU (2-second sample)</h3><div class="big">${cpuPct.toFixed(0)}% <span class="small">of ${cores} cores</span></div>
    <div class="meter">${seg(cpuPct,100,cpuPct>70?'var(--caution)':'var(--bar)')}</div>
    <div class="small">Load avg ${(h.load||[]).map(x=>x.toFixed(2)).join(' / ')} · up ${h.uptime_days??'?'} days · ${pr.nprocs||0} processes</div>
    <div class="small">Top: ${topCpu||'-'}</div></div>`;
}

function tabs(){
  document.getElementById('tabs').innerHTML = SECTIONS.map(([k,l])=>{
    let cnt='';
    if(k!=='overview'){const its=itemsIn(k); if(!its.length && k!=='processes') return ''; cnt=`<span class="cnt">${its.length}</span>`}
    return `<button data-tab="${k}" class="${state.tab===k?'on':''}">${l}${cnt}</button>`}).join('');
}

function overview(){
  const sp = itemsIn('space').slice().sort((a,b)=>b.size-a.size);
  const groups = {};
  sp.forEach(i=>{(groups[i.category] = groups[i.category]||[]).push(i)});
  const block = (title, arr) => { if(!arr||!arr.length) return ''; const max = arr[0].size||1;
    return `<div class="card"><h3>${esc(title)}</h3>${arr.map(i=>`<div class="srow" title="${esc(i.impact||i.path)}">
      <div class="t">${esc(i.name)}</div><div class="strack"><span style="width:${(i.size/max*100).toFixed(1)}%"></span></div>
      <div class="num small" style="text-align:right">${hb(i.size)}</div></div>${i.impact?`<div class="note" style="margin:-2px 0 4px">${esc(i.impact)}</div>`:''}`).join('')}</div>`};
  const sizesBySec = SECTIONS.slice(1).filter(([k])=>!['processes','background'].includes(k)).map(([k,l])=>{
    const its=itemsIn(k).filter(i=>i.deletable); return [l, its.reduce((a,i)=>a+i.size,0), its.filter(i=>i.safety==='safe').reduce((a,i)=>a+i.size,0), k]}).filter(x=>x[1]>0);
  const maxS = Math.max(1,...sizesBySec.map(x=>x[1]));
  return `<div class="grid2" style="margin-top:12px">
    <div class="card"><h3>Recommendations</h3><ul class="recs">${(D.recs||[]).map(r=>`<li><span class="dot d-${r.level}"></span><span>${esc(r.text)}</span></li>`).join('')}</ul></div>
    <div class="card"><h3>Cleanable space by tab</h3>${sizesBySec.map(([l,t,s,k])=>`<div class="srow" style="cursor:pointer" data-goto="${k}">
       <div class="t">${esc(l)}</div><div class="strack"><span style="width:${(t/maxS*100).toFixed(1)}%;background:linear-gradient(90deg,var(--safe) ${(s/t*100).toFixed(1)}%,var(--review) ${(s/t*100).toFixed(1)}%)"></span></div>
       <div class="num small" style="text-align:right">${hb(t)}</div></div>`).join('')}
       <div class="small" style="margin-top:6px"><span style="color:var(--safe)">■</span> Safe <span style="color:var(--review)">■</span> Review / caution</div>
       <h3 style="margin-top:14px">Safety levels</h3>${['safe','review','caution','protected'].map(s=>`<div class="note">${badge(s)} ${esc(SAFETY_HELP[s])}</div>`).join('')}</div>
  </div>
  <div class="grid2" style="margin-top:12px">${block('Home folder', groups['Home folder'])}${block('~/Library', groups['~/Library'])}</div>
  <div class="grid2" style="margin-top:12px">${block('Application Support', groups['Application Support'])}${block('Containers', groups['Containers'])}</div>
  <div class="grid2" style="margin-top:12px">${block('Group Containers', groups['Group Containers'])}</div>`;
}

function filtered(sec){
  let its = itemsIn(sec);
  if(state.safety!=='all') its = its.filter(i=>i.safety===state.safety);
  if(state.q){const q=state.q.toLowerCase(); its = its.filter(i=>(i.name+' '+i.path+' '+i.category+' '+i.impact+' '+i.note).toLowerCase().includes(q))}
  const {key,dir} = state.sort;
  const val = i => key==='size'?i.size : key==='cpu'?(i.meta.cpu_now||0) : key==='safety'?['safe','review','caution','protected','info'].indexOf(i.safety) : key==='used'?(i.meta.unused_days??99999) : String(i[key]||'').toLowerCase();
  its.sort((a,b)=>{const x=val(a),y=val(b);return (x<y?-1:x>y?1:0)*dir});
  return its;
}

function statusCell(i){
  if(i.status==='done') return `<div class="st-ok">✓ ${esc(i.status_msg||'done')}</div>`;
  if(i.status==='error') return `<div class="st-err">✗ ${esc(i.status_msg||'failed')}</div>`;
  if(i._dry) return `<div class="small">${esc(i._dry)}</div>`;
  return '';
}

function tagList(i){
  const t=[]; if(i.note) i.note.split(' · ').forEach(x=>x&&t.push(x));
  if(i.kind==='app' && i.meta.support_size) t.push('+'+hb(i.meta.support_size)+' support files');
  if(i.meta.version) t.push('v'+i.meta.version);
  return t.map(x=>`<span class="tag">${esc(x)}</span>`).join('');
}

function table(sec){
  const its = filtered(sec);
  const all = itemsIn(sec);
  const counts = {}; all.forEach(i=>counts[i.safety]=(counts[i.safety]||0)+1);
  const chips = ['all','safe','review','caution','protected','info'].filter(s=>s==='all'||counts[s])
    .map(s=>`<button class="chip ${state.safety===s?'on':''}" data-safety="${s}">${s==='all'?'All':SAFETY_LABEL[s]} ${s==='all'?all.length:counts[s]}</button>`).join('');
  const total = its.reduce((a,i)=>a+i.size,0);
  const isProc = sec==='processes';
  const intro = {
    storage:'Caches, logs, device backups, installers and other files that build up over time.',
    apps:'Apps in /Applications and ~/Applications. "Last used" comes from Spotlight. Uninstall moves the app (and optionally its support files) to the Trash.',
    dev:'Developer caches, Docker, Xcode, Homebrew and local AI models. Most re-download or rebuild when needed.',
    projects:'Dependency folders inside your projects. Safe to delete for projects you are not actively working on - reinstall later with the command shown.',
    files:'Big files in your home folder and everything sizeable in Downloads. These are your files - review each one.',
    leftovers:'Data in ~/Library that belongs to apps that no longer seem to be installed.',
    background:'Things that start automatically: launch agents (at login), launch daemons (at boot, as root), login items and Homebrew services. Removing them reduces background CPU/memory use.',
    processes:'Memory (RSS, includes shared memory) and CPU per app, grouped (e.g. all Chrome helpers together). CPU "now" is a 2-second sample; 100% = one full core. Quitting frees memory; it does not change disk space.'}[sec]||'';
  const head = isProc
    ? `<tr><th></th><th data-sort="name">Process / app</th><th data-sort="category">Kind</th><th class="num" data-sort="size">Memory</th><th class="num" data-sort="cpu">CPU now</th><th class="num">Procs</th><th data-sort="safety">Safety</th><th>What it is / what happens if you quit it</th><th></th></tr>`
    : `<tr><th></th><th data-sort="name">Item</th><th data-sort="category">Category</th><th class="num" data-sort="size">Size</th><th data-sort="safety">Safety</th>${sec==='apps'?'<th class="num" data-sort="used">Last used</th>':''}<th>What happens if you remove it</th><th></th></tr>`;
  const rows = its.map(i=>{
    const dis = !i.deletable || i.status==='done';
    const cb = `<input type="checkbox" data-id="${i.id}" ${state.sel.has(i.id)?'checked':''} ${dis?'disabled':''} title="${dis?(i.status==='done'?'Done':'Protected / informational'):esc(i.action||'')}">`;
    const acts = `${SERVER && i.path && i.kind!=='command' && i.kind!=='process'?`<button class="link" data-reveal="${i.id}">Reveal</button>`:''}${i.export?`<button class="link" data-copy="${i.id}">Copy cmd</button>`:''}${statusCell(i)}`;
    const nameCell = `<div class="n">${esc(i.name)}</div>${i.path && i.path!==i.name?`<div class="p">${esc(i.path)}</div>`:''}${tagList(i)}`;
    if(isProc) return `<tr class="${i.status==='done'?'done':''}"><td>${cb}</td><td>${nameCell}</td><td class="small">${esc(i.category)}</td>
      <td class="num">${i.size?hb(i.size):'-'}</td><td class="num">${i.meta.cpu_now!=null?i.meta.cpu_now.toFixed(1)+'%':'-'}</td><td class="num">${i.meta.nprocs||''}</td>
      <td>${badge(i.safety)}</td><td class="impact">${esc(i.impact)}</td><td class="acts">${acts}</td></tr>`;
    const lu = sec==='apps' ? `<td class="num small">${i.meta.unused_days==null?'never/unknown':i.meta.unused_days===0?'today':i.meta.unused_days+' d ago'}</td>` : '';
    return `<tr class="${i.status==='done'?'done':''}"><td>${cb}</td><td>${nameCell}</td><td class="small">${esc(i.category)}</td>
      <td class="num">${i.size?hb(i.size):'<span class="small">?</span>'}</td><td>${badge(i.safety)}</td>${lu}<td class="impact">${esc(i.impact)}</td><td class="acts">${acts}</td></tr>`;
  }).join('');
  return `<p class="hint">${esc(intro)}</p>
  <div class="toolbar"><input type="search" id="q" placeholder="Filter by name, path, category…" value="${esc(state.q)}">${chips}
  <span class="spacer"></span><span class="small">${its.length} shown · ${hb(total)}</span>
  <button class="btn" data-selsafe="${sec}">Select all Safe</button><button class="btn" data-selvisible="${sec}">Select shown</button></div>
  <div class="tablewrap"><table><thead>${head}</thead><tbody>${rows||`<tr><td colspan="9" class="empty">Nothing here${state.q||state.safety!=='all'?' for this filter':''}.</td></tr>`}</tbody></table></div>`;
}

function render(){
  tabs();
  const c = document.getElementById('content');
  c.innerHTML = state.tab==='overview' ? overview() : table(state.tab);
  const q = document.getElementById('q');
  if(q){q.oninput = e=>{state.q=e.target.value; const pos=e.target.selectionStart; render(); const n=document.getElementById('q'); n.focus(); n.setSelectionRange(pos,pos)}}
  updateBar();
}

function updateBar(){
  const sel=[...state.sel].map(id=>BYID[id]).filter(Boolean);
  const disk=sel.filter(i=>i.section!=='processes').reduce((a,i)=>a+i.size+(i.kind==='app'&&document.getElementById('inclSupport').checked?(i.meta.support_size||0):0),0);
  const mem=sel.filter(i=>i.section==='processes').reduce((a,i)=>a+i.size,0);
  document.getElementById('selinfo').textContent = sel.length ? `${sel.length} selected · ${hb(disk)} disk${mem?` · ${hb(mem)} memory`:''}` : 'Nothing selected';
  const go=document.getElementById('go'); go.disabled=!sel.length;
  go.textContent = SERVER ? 'Review & clean up…' : 'Export as shell script…';
  document.getElementById('finish').style.display = SERVER?'':'none';
}

document.addEventListener('click', e=>{
  const t=e.target.closest('[data-tab],[data-safety],[data-sort],[data-selsafe],[data-selvisible],[data-reveal],[data-copy],[data-goto]');
  if(!t) return;
  if(t.dataset.tab||t.dataset.goto){state.tab=t.dataset.tab||t.dataset.goto; state.safety='all'; state.q=''; render(); window.scrollTo({top:0})}
  else if(t.dataset.safety){state.safety=t.dataset.safety; render()}
  else if(t.dataset.sort){const k=t.dataset.sort; state.sort = state.sort.key===k?{key:k,dir:-state.sort.dir}:{key:k,dir:(k==='size'||k==='cpu')?-1:1}; render()}
  else if(t.dataset.selsafe){itemsIn(t.dataset.selsafe).forEach(i=>{if(i.deletable&&i.safety==='safe'&&i.status!=='done') state.sel.add(i.id)}); render()}
  else if(t.dataset.selvisible){filtered(t.dataset.selvisible).forEach(i=>{if(i.deletable&&i.status!=='done') state.sel.add(i.id)}); render()}
  else if(t.dataset.reveal){api('/api/reveal',{id:t.dataset.reveal})}
  else if(t.dataset.copy){copy(BYID[t.dataset.copy].export); t.textContent='Copied'; setTimeout(()=>t.textContent='Copy cmd',1200)}
});
document.addEventListener('change', e=>{
  const id=e.target.dataset&&e.target.dataset.id;
  if(id){e.target.checked?state.sel.add(id):state.sel.delete(id); updateBar()}
});
document.getElementById('inclSupport').onchange=updateBar;
document.getElementById('clearSel').onclick=()=>{state.sel.clear(); render()};
document.getElementById('go').onclick=()=>SERVER?review():exportScript();
document.getElementById('finish').onclick=async()=>{await api('/api/shutdown',{}); document.body.innerHTML='<div class="empty"><h2>Finished</h2><p>The local server has stopped. You can close this tab. Removed items are in your Trash (folder "Mac Cleanup …").</p></div>'};

function copy(txt){
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(txt);return}
  const ta=document.createElement('textarea'); ta.value=txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
}
async function api(path, body){
  const r = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Token':D.token},body:JSON.stringify(body)});
  return r.json();
}
function modal(title, body, buttons){
  document.getElementById('mh').innerHTML=`<h2 style="margin:0;font-size:18px">${title}</h2>`;
  document.getElementById('mb').innerHTML=body;
  const f=document.getElementById('mf'); f.innerHTML='';
  buttons.forEach(([label,cls,fn])=>{const b=document.createElement('button'); b.className='btn '+(cls||''); b.innerHTML=label; b.onclick=fn; f.appendChild(b)});
  document.getElementById('modalbg').style.display='flex';
}
const closeModal=()=>document.getElementById('modalbg').style.display='none';
document.getElementById('modalbg').onclick=e=>{if(e.target.id==='modalbg') closeModal()};

function review(){
  const sel=[...state.sel].map(id=>BYID[id]).filter(Boolean);
  const mode=document.getElementById('mode').value, incl=document.getElementById('inclSupport').checked;
  const warn=[];
  if(mode==='delete') warn.push('<b>Permanent delete</b> is selected: files will NOT go to the Trash and cannot be recovered.');
  const caution=sel.filter(i=>i.safety==='caution'); if(caution.length) warn.push(`${caution.length} item(s) are marked <b>Caution</b>: ${caution.map(i=>esc(i.name)).join(', ')}.`);
  const apps=sel.filter(i=>i.kind==='app');
  if(apps.length && incl) warn.push(`App support files will also be removed for ${apps.length} app(s) - this includes their settings and any data they store internally.`);
  const running=apps.filter(i=>i.meta.running); if(running.length) warn.push(`Running apps will be asked to quit first: ${running.map(i=>esc(i.name)).join(', ')}.`);
  const procs=sel.filter(i=>i.kind==='process'); if(procs.length) warn.push(`${procs.length} app(s)/process(es) will be quit or terminated - save your work first.`);
  if(sel.some(i=>/password|admin/i.test(i.impact)||i.path.startsWith('/Library/')||i.export.startsWith('sudo'))) warn.push('Some items need administrator rights - macOS will ask for your password once.');
  const order={caution:0,review:1,safe:2};
  const list=sel.slice().sort((a,b)=>(order[a.safety]??3)-(order[b.safety]??3)||b.size-a.size).map(i=>
    `<div class="mitem">${badge(i.safety)} <b>${esc(i.name)}</b> <span class="small">${i.size?hb(i.size):''} · ${esc(i.action||'')}</span><div class="note">${esc(i.impact)}</div></div>`).join('');
  modal(`Clean up ${sel.length} item(s)?`,
    `${warn.map(w=>`<div class="warnbox">${w}</div>`).join('')}
     <p class="small">Action: <b>${mode==='trash'?'Move to Trash (recoverable - everything goes into one "Mac Cleanup …" folder in the Trash with a RESTORE.txt)':'Delete permanently'}</b>. Commands (Docker, Homebrew, Ollama…) run as shown with "Copy cmd".</p>${list}`,
    [['Cancel','',closeModal],['Preview (dry run)','',()=>run(true)],[mode==='delete'?'Delete permanently':'Clean up','danger',()=>run(false)]]);
}

async function run(dry){
  const ids=[...state.sel];
  const mode=document.getElementById('mode').value, incl=document.getElementById('inclSupport').checked;
  modal(dry?'Previewing…':'Working…','<p>Please wait. If macOS shows a password or permission dialog, answer it.</p>',[]);
  let res;
  try{res=await api('/api/execute',{ids,mode,dry_run:dry,include_support:incl})}
  catch(e){modal('Error',`<p>Could not reach the local server (${esc(e)}). Is the script still running in Terminal?</p>`,[['Close','',closeModal]]);return}
  let ok=0,fail=0,freed=0;
  res.results.forEach(r=>{const i=BYID[r.id]; if(!i) return;
    if(dry){i._dry=r.msg} else {i._dry=null; i.status=r.ok?'done':'error'; i.status_msg=r.msg; if(r.ok){ok++; freed+=i.section!=='processes'?i.size:0; state.sel.delete(r.id)} else fail++}});
  const lines=res.results.map(r=>`<div class="mitem">${r.ok?'<span class="st-ok">✓</span>':'<span class="st-err">✗</span>'} <b>${esc(BYID[r.id]?.name||r.id)}</b><div class="note">${esc(r.msg)}</div></div>`).join('');
  render();
  modal(dry?'Dry run - nothing was changed':`Done: ${ok} succeeded${fail?`, ${fail} failed`:''}`,
    `${dry?'':`<p>About <b>${hb(freed)}</b> cleaned up.${res.trash_folder?` Moved items are in <code>${esc(res.trash_folder)}</code> - empty the Trash to actually free the space.`:''}</p>`}${lines}`,
    dry?[['Close','',closeModal],['Run it for real','danger',()=>run(false)]]:[['Close','',closeModal]]);
}

function exportScript(){
  const sel=[...state.sel].map(id=>BYID[id]).filter(i=>i&&i.export);
  const txt=['#!/bin/bash','# Generated by mac_cleanup.py on '+D.generated,'# Review every line before running. Items are moved to ~/.Trash where possible.','set -u',''].concat(
    sel.map(i=>`# ${i.name} (${hb(i.size)}, ${SAFETY_LABEL[i.safety]}) - ${i.impact.replace(/\n/g,' ')}\n${i.export}\n`)).join('\n');
  modal('Shell script for selected items',`<p class="small">Save as cleanup.sh, read it, then run <code>bash cleanup.sh</code>.</p><pre>${esc(txt)}</pre>`,
    [['Close','',closeModal],['Copy','',()=>copy(txt)],['Download','primary',()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([txt],{type:'text/x-shellscript'}));a.download='cleanup.sh';a.click()}]]);
}

header(); render();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
