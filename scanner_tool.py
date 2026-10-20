"""
CVE: Barcode Scanner Config Tool (c) UZ Leuven IT | Chris Vermeijlen
Python translation of DatalogicGM4500Configr10VoorHelpdesk.ps1

- Splash screen (5 s) with title + UZ Leuven logo
- Scan: COM ports from HKLM\\HARDWARE\\DEVICEMAP\\SERIALCOMM,
  brand from Win32_PnPEntity (Datalogic = green, others = red)
- Load config: full Datalogic push procedure
  ($+$! version -> cradle type -> config file -> $S service mode
   -> 115200 -> line per line with OK/NOK -> $Ar save -> $s exit)
- VCOM / Unlink / Honeywell barcode dialogs (images extracted from
  the original .ps1 by extract_barcodes.py)
- Ghost COM port cleanup (pnputil), Datalogic driver check
- Log to C:\\uz\\Logs\\DatalogicGM4500Configr10VoorHelpdesk.log
"""

import os
import time
import queue
import threading
import subprocess
import winreg
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk, ImageDraw

try:
    import serial
except ImportError:
    serial = None

LOGO_PATH = "uz_leuven_logo.png"
SPLASH_SECONDS = 5000  # ms

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = r"C:\uz\Logs"
LOG_FILE = os.path.join(LOG_DIR, "DatalogicGM4500Configr10VoorHelpdesk.log")

CONFIG_FILES = {
    "GM4500": "configuratie.txt",
    "GM4400": "configuratieoud.txt",
    "GM4600": "gm4600.txt",
}

DRIVER_PATH = r"C:\Program Files (x86)\Datalogic\USBCOMInstaller"
DRIVER_MSI = (r"\\uz\data\software\SCCMInstall\Scanners\Datalogic Gryphon GM4500"
              r"\USB-COM_Driver_v6.3.2\USBCOMInstaller.msi")
HONEYWELL_DRIVER_OLD = (r"C:\Program Files\Honeywell"
                        r"\Honeywell HSM USB Serial Drv x64 ver 3.5.18")

BAUD_NORMAL = 9600
BAUD_SERVICE = 115200
READ_TIMEOUT = 10
WRITE_TIMEOUT = 6

BARCODE_FILES = {
    "vcom": "vcom.jpg",
    "unlink": "unlink.jpg",
    "honeywell": "honeywell.png",
}
ICON_FILE = "icon.png"


# ------------------------------------------------------------------ logging
class Logger:
    def __init__(self, gui_queue):
        self.q = gui_queue
        os.makedirs(LOG_DIR, exist_ok=True)

    def __call__(self, msg):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
                f.write(f"[{stamp}] {msg}\n")
        except OSError:
            pass
        self.q.put(msg)


def log_countdown(log, seconds):
    for i in range(seconds, 0, -1):
        log(f" {i} ")
        time.sleep(1)


# ------------------------------------------------------------------ devices
def read_serialcomm():
    """Return dict {device_name: com_port} from HKLM SERIALCOMM."""
    result = {}
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"HARDWARE\DEVICEMAP\SERIALCOMM", 0,
                             winreg.KEY_READ)
    except FileNotFoundError:
        return result
    with key:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            result[name] = value
            i += 1
    return result


DEVICE_PATTERNS = [
    ("datalogic", "Barcode Scanner (COM"),
    ("honeywell", "Honeywell Scanning Solution (COM"),
    ("xenon", "Xenon 1900 Area-Imaging Scanner (COM"),
    ("unknown", "USBSER000"),
]

BRAND_LABELS = {
    "datalogic": "Datalogic",
    "honeywell": "Honeywell",
    "xenon": "Honeywell Xenon 1900",
    "unknown": "Unknown",
}


def get_pnp_entities():
    """Return list of (name, port, brand) for PnP entities matching the
    known scanner patterns (same classification as the .ps1)."""
    entities = []
    try:
        import wmi
        c = wmi.WMI()
        for dev in c.Win32_PnPEntity():
            nm = dev.Name or ""
            for brand, pattern in DEVICE_PATTERNS:
                if pattern not in nm:
                    continue
                port = _port_from_name(nm)
                if port:
                    entities.append((nm, port, brand))
                break
    except ImportError:
        raise RuntimeError("The 'wmi' package is required for device "
                           "detection (pip install wmi pywin32)")
    except Exception:
        pass
    return entities


def _port_from_name(nm):
    """Extract COMx from a name like 'Barcode Scanner (COM3)'."""
    idx = nm.rfind("(COM")
    if idx != -1 and nm.endswith(")"):
        return nm[idx + 1:-1]
    return None


def remove_hidden_devices(log):
    """Remove ghost COM ports: PnP devices of class Ports with
    status Unknown, removed via pnputil (same as RemoveHiddenDevices)."""
    ps = ("Get-PnpDevice -Class Ports -ea 0 | "
          "Where-Object {$_.Status -eq 'Unknown'} | "
          "Select-Object -ExpandProperty InstanceId")
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=60).stdout
    except Exception as e:
        log(f" Error querying ghost COM ports: {e}")
        return
    instances = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not instances:
        log("Er zijn geen spook com poorten")
        return
    log("Opruimen van spook com poorten")
    for inst in instances:
        log(f"{inst} wordt verwijderd")
        subprocess.run(["pnputil", "/remove-device", inst],
                       capture_output=True, text=True)


def datalogic_driver_check(log, parent):
    """Same as datalogicDriver: verify the Datalogic USB-COM driver,
    offer installation of the MSI from the UZ share if absent."""
    if os.path.isdir(DRIVER_PATH):
        log("Datalogic driver is al geinstalleerd op computer")
        return
    if messagebox.askyesno(
            "Datalogic driver",
            "Datalogic driver is niet geinstalleerd.\n"
            "Installeren vanaf \\\\uz\\data ?", parent=parent):
        try:
            subprocess.Popen(["msiexec", "/i", DRIVER_MSI,
                              "/quiet", "/passive"])
            log("Waiting until driver is installed and device is online")
            log_countdown(log, 6)
        except Exception as e:
            log(f" Error starting driver install: {e}")
    else:
        log(" Datalogic driver niet geinstalleerd, installatie overgeslaan")


def honeywell_driver_check(log):
    """Same as CheckDriverHoneywell."""
    log("Checking driver version Honeywell")
    if os.path.isdir(HONEYWELL_DRIVER_OLD):
        log("Systeem heeft een oude driver, poging om de nieuwe te "
            "installeren (uz_install_honeywell3.5.24.ps1)")
    else:
        log("Systeem bevat de juiste Honeywell driver")


# ------------------------------------------------------- serial helpers
def read_existing(ser):
    """Non-blocking read of whatever is in the buffer (ReadExisting)."""
    n = ser.in_waiting
    if n:
        return ser.read(n).decode("ascii", "ignore")
    return ""


def wait_reply(ser):
    """Poll every 10 ms until the device answered something."""
    out = ""
    while out == "":
        time.sleep(0.01)
        out = read_existing(ser)
    return out


def is_ok(reply):
    return reply.replace("\r", "").replace("\n", "").strip() == "$>"


# ------------------------------------------------------- push config (Datalogic)
def push_config(port, log, on_done):
    """Full translation of the Datalogic branch of PushConfig."""
    if serial is None:
        log("pyserial is niet geinstalleerd (pip install pyserial)")
        on_done(False)
        return
    port_obj = None
    port2_obj = None
    ok_count = 0
    fail_count = 0
    lines_in_conf = 0
    try:
        # ---- open port @ 9600 (RTS + DTR asserted, as in the .ps1)
        try:
            port_obj = serial.Serial(port=port, baudrate=BAUD_NORMAL,
                                     bytesize=8, parity="N", stopbits=1,
                                     rts=True, dtr=True,
                                     timeout=READ_TIMEOUT,
                                     write_timeout=WRITE_TIMEOUT)
        except Exception as e:
            log(" Error trying to open the comport")
            log(" Please close the script and all programs using the "
                "COM-port (KWS, Putty,...) or the scanner for that matter")
            log(f" {e}")
            on_done(False)
            return
        log(f" Open {port} @ {BAUD_NORMAL} 8N1 (RTS/DTR on)")

        # ---- read software version
        scanner_type = None
        try:
            port_obj.write(b"$+$!\r")
            time.sleep(0.5)
            output = read_existing(port_obj)
            log(f" SOFTWARE VERSION: {output}")
            log(" " + "-" * 80)
            if len(output) < 7:
                log(" Error while retrieving software version (no reply)")
                on_done(False)
                return
            type_cradle = output[0:7]
            if type_cradle in ("WLC4090", "WLC4190"):
                scanner_type = "GM4500"
                log(" This is a GM4500 scanner")
            elif type_cradle.startswith("BC40x0"):
                scanner_type = "GM4400"
                log(" This is a GM4400 scanner")
            elif type_cradle == "WLC4690":
                scanner_type = "GM4600"
                log(" This is a GM4600 scanner")
            if scanner_type is None:
                log(f" Onbekend craddle type: {type_cradle!r} - "
                    f"configuratie niet verstuurd")
                on_done(False)
                return
            try:
                idx = output.index("SOFTWARE RELEASE")
                software_release = output[idx + 17: idx + 26]
                log(f" Type craddle: {type_cradle}")
                log(f" Firmwareversion Craddle: {software_release}")
                if type_cradle == "WLC4190" and software_release < "610150127":
                    log(" There is a new firmware for this craddle")
                if type_cradle == "WLC4090" and software_release < "610116050":
                    log(" There is a new firmware for this craddle")
            except ValueError:
                log(" Kon firmwareversie niet bepalen uit het antwoord")
        except Exception as e:
            log(" Error while retrieving software version")
            log(f" {e}")

        # ---- load the configuration file for this scanner type
        conf_path = os.path.join(SCRIPT_DIR, CONFIG_FILES[scanner_type])
        if not os.path.isfile(conf_path):
            log(f" Configuratiebestand niet gevonden: {conf_path}")
            on_done(False)
            return
        with open(conf_path, "r") as f:
            configuration = [ln.rstrip("\r\n") for ln in f]
        lines_in_conf = len(configuration)

        # ---- service mode
        log(" Putting device in service mode")
        port_obj.write(b"$S\r")
        log(" Waiting until device is back online (3 s)")
        log_countdown(log, 3)
        output = read_existing(port_obj)
        if is_ok(output):
            log(" Device: OK")
            log(" Device is in service mode")
        else:
            log(" Device: NOK")
            log(" Something went wrong putting the device in service mode")
            on_done(False)
            return

        # ---- switch to 115200
        port_obj.close()
        log(f" Close port {port} @ {BAUD_NORMAL}")
        time.sleep(1)
        log(f" Open port {port} @ {BAUD_SERVICE}")
        time.sleep(1)
        port2_obj = serial.Serial(port=port, baudrate=BAUD_SERVICE,
                                  bytesize=8, parity="N", stopbits=1,
                                  rts=True, dtr=True,
                                  timeout=READ_TIMEOUT,
                                  write_timeout=WRITE_TIMEOUT)
        time.sleep(1)

        # ---- send configuration line per line
        log(f" Sending configuration to device on {port}")
        for line in configuration:
            port2_obj.write(("$" + line + "\r").encode("ascii"))
            log(f" HOST: {line}")
            output = wait_reply(port2_obj)
            if is_ok(output):
                log(" Device: OK")
                ok_count += 1
            else:
                log(f" Device: NOK  ({output!r})")
                fail_count += 1
            time.sleep(0.03)
        time.sleep(0.03)

        # ---- save settings
        log(" HOST: Saving settings onto device")
        port2_obj.write(b"$Ar\r")
        log(" Waiting until device is back online (5 s)")
        log_countdown(log, 5)

        # ---- close service mode
        log(" HOST: Closing service mode")
        try:
            if port2_obj.is_open:
                port2_obj.write(b"$s\r")
                log(" Waiting until device is out of service mode (4 s)")
                log_countdown(log, 4)
            else:
                log(f" De poort is dicht, geen ramp als {ok_count} = "
                    f"{lines_in_conf} :)")
        except Exception as e:
            log(" De poort is dicht of de scanner reageerde te snel, "
                f"geen ramp als {ok_count} = {lines_in_conf} :)")
            log(f" {e}")

        log(" HOST: close port")
        port2_obj.close()
        if port2_obj.is_open:
            log(" port is still open")
        else:
            log(f" Port {port} is closed")

        # ---- summary
        if ok_count == lines_in_conf:
            log(f" All lines ({ok_count}) from configuration are written "
                f"correctly onto device")
            log(" We moeten de gun nog unlinken (scan de unlink barcode)")
        else:
            log(" " + "-" * 80)
            log(" Something went wrong, contact Chris V of Krispey")
            log(f" {fail_count} lines are not written onto device.")
            log(f" {ok_count} are written correctly onto device "
                f"({lines_in_conf} expected)")
            log(f" This is a {scanner_type} scanner")
            log(" " + "-" * 80)
        on_done(ok_count == lines_in_conf)
    finally:
        for p in (port_obj, port2_obj):
            if p is not None:
                try:
                    if p.is_open:
                        p.close()
                        log(" port closed (cleanup)")
                except Exception:
                    pass


# ------------------------------------------------------------------ images
def load_logo(size=(200, 90)):
    here = SCRIPT_DIR
    for cand in (LOGO_PATH, os.path.join(here, LOGO_PATH)):
        if os.path.isfile(cand):
            try:
                img = Image.open(cand).convert("RGBA")
                img.thumbnail(size, Image.LANCZOS)
                return img
            except Exception:
                pass
    w, h = size
    img = Image.new("RGBA", size, (255, 255, 255, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([4, 4, w - 4, h - 4], radius=14,
                        fill=(0, 62, 138, 255))
    d.text((w // 2, h // 2), "UZ LEUVEN", fill="white", anchor="mm")
    d.text((w // 2, h // 2 + 22), "Universitair Ziekenhuis",
           fill=(200, 220, 245, 255), anchor="mm")
    return img


def load_barcode(kind):
    """Load barcode image extracted by extract_barcodes.py (images/)."""
    path = os.path.join(SCRIPT_DIR, "images", BARCODE_FILES.get(kind, ""))
    if os.path.isfile(path):
        try:
            return Image.open(path)
        except Exception:
            return None
    return None


# ------------------------------------------------------------------ dialogs
class VcomDialog(tk.Toplevel):
    """Translation of ShowVcom: barcode image with Gescant / Niet gescant."""

    def __init__(self, parent, kind, log):
        super().__init__(parent)
        self.kind = kind
        self.log = log
        self.title("Barcode VCOM")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        tk.Label(self, text="(c)UZ Leuven IT | Chris Vermeijlen",
                 anchor="w").pack(fill="x", padx=10, pady=(10, 4))

        img = load_barcode(kind)
        if img is None:
            tk.Label(self, text="Barcode image niet gevonden.\n"
                     "Draai eerst extract_barcodes.py om de images uit "
                     "de originele .ps1 te halen.",
                     fg="red", justify="left").pack(padx=20, pady=20)
        else:
            self._photo = ImageTk.PhotoImage(img, master=self)
            tk.Label(self, image=self._photo).pack(padx=10, pady=6)

        btns = tk.Frame(self)
        btns.pack(pady=10)
        tk.Button(btns, text="Gescant", width=12,
                  command=self._ok).grid(row=0, column=0, padx=6)
        tk.Button(btns, text="Niet gescant", width=12,
                  command=self._cancel).grid(row=0, column=1, padx=6)

        icon_path = os.path.join(SCRIPT_DIR, "images", ICON_FILE)
        if os.path.isfile(icon_path):
            try:
                self.iconphoto(False, ImageTk.PhotoImage(
                    Image.open(icon_path), master=self))
            except Exception:
                pass

    def _ok(self):
        if self.kind == "unlink":
            self.log("De scanner gaat nu unlinken en terug linken (10 s)")
            self.after(10, lambda: self._countdown(10))
            return
        self.log(" Het scannen van de barcode is gelukt.\n  Opgelet:\n"
                 "  >>>> Voor de initiële configuratie van een gryphon "
                 "dient u dit script NOGMAALS te laten lopen <<<<")
        self.destroy()

    def _cancel(self):
        self.log("De code is niet gescant, gelieve iemand langs te "
                 "sturen. Mogelijks is een powercycle van de gun nodig")
        self.destroy()

    def _countdown(self, n):
        if n > 0:
            self.log(f" {n} ")
            self.after(1000, lambda: self._countdown(n - 1))
        else:
            self.destroy()


# ------------------------------------------------------------------ splash
def show_splash(root):
    splash = tk.Toplevel(root)
    splash.overrideredirect(True)
    splash.attributes("-topmost", True)
    splash.configure(bg="white")

    tk.Label(splash, text="CVE: Barcode Scanner Config Tool",
             font=("Segoe UI", 16, "bold"), bg="white",
             fg="#003E8A").pack(pady=(30, 10))

    logo_img = ImageTk.PhotoImage(load_logo(), master=splash)
    lbl = tk.Label(splash, image=logo_img, bg="white")
    lbl.image = logo_img
    lbl.pack(padx=40, pady=(0, 20), fill="both", expand=True)

    splash.update_idletasks()
    w, h = splash.winfo_reqwidth(), max(splash.winfo_reqheight(), 300)
    x = (splash.winfo_screenwidth() - w) // 2
    y = (splash.winfo_screenheight() - h) // 2
    splash.geometry(f"{w}x{h}+{x}+{y}")
    splash.after(SPLASH_SECONDS, splash.destroy)
    return splash


# ------------------------------------------------------------------ main app
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CVE: Barcode Scanner Config Tool")
        self.geometry("980x680")
        self.minsize(800, 520)
        self.withdraw()

        self.log_queue = queue.Queue()
        self.log = Logger(self.log_queue)
        self.ports = {}
        self.entities = []
        self.busy = False

        self.logo_img = ImageTk.PhotoImage(load_logo((140, 60)), master=self)
        self._build_ui()
        show_splash(self)
        self.after(SPLASH_SECONDS, self.deiconify)
        self.after(100, self._poll_log)

        self.log("=" * 80)
        self.log("CVE Barcode Scanner Config Tool gestart")
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.log(" WAARSCHUWING: script draait niet als "
                         "administrator (poorten opruimen / driver "
                         "installeren vereist admin)")
        except Exception:
            pass

    # ------------------------------------------------------------- UI
    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=(10, 4))
        ttk.Label(top, image=self.logo_img).pack(side="right")
        ttk.Label(top, text="CVE: Barcode Scanner Config Tool",
                  font=("Segoe UI", 13, "bold")).pack(side="left")

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=12, pady=8)
        self.btn_scan = ttk.Button(btns, text="Scan", command=self.on_scan)
        self.btn_scan.pack(side="left", padx=4)
        self.btn_load = ttk.Button(btns, text="Load Config",
                                   command=self.on_load_config)
        self.btn_load.pack(side="left", padx=4)
        ttk.Button(btns, text="VCOM barcode",
                   command=lambda: self._show_vcom("vcom")).pack(
                       side="left", padx=4)
        ttk.Button(btns, text="Unlink barcode",
                   command=lambda: self._show_vcom("unlink")).pack(
                       side="left", padx=4)
        self.btn_clean = ttk.Button(btns, text="Clean ghost ports",
                                    command=self.on_clean_ports)
        self.btn_clean.pack(side="left", padx=4)
        ttk.Button(btns, text="Exit", command=self.destroy).pack(
            side="right", padx=4)

        cols = ("name", "port", "status", "load")
        self.tree = ttk.Treeview(self, columns=cols, show="headings",
                                 selectmode="browse", height=10)
        headers = {
            "name": ("Name", 340, "w"),
            "port": ("Port", 80, "w"),
            "status": ("Status", 140, "center"),
            "load": ("Load", 120, "center"),
        }
        for c in cols:
            txt, w, anchor = headers[c]
            self.tree.heading(c, text=txt)
            self.tree.column(c, width=w, anchor=anchor, stretch=(c == "name"))
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0, 4))
        self.tree.tag_configure("datalogic", foreground="#1a7a1a")
        self.tree.tag_configure("other", foreground="#b02020")
        self.tree.bind("<Button-1>", self._on_tree_click)

        ttk.Label(self, text="Log:").pack(anchor="w", padx=12)
        self.logpane = ScrolledText(self, height=12, state="disabled",
                                    font=("Consolas", 9))
        self.logpane.pack(fill="both", expand=False, padx=12, pady=(0, 8))

        self.status = tk.Label(self, text="Ready. Click Scan to list COM ports.",
                              anchor="w", bd=1, relief="sunken")
        self.status.pack(fill="x", side="bottom")

    # ------------------------------------------------------------- helpers
    def _poll_log(self):
        while True:
            try:
                msg = self.log_queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(msg, tuple):
                if msg[0] == "__rows__":
                    self._fill_table(msg[1], msg[2])
                elif msg[0] == "__done__":
                    self._set_busy(False)
                continue
            self.logpane.configure(state="normal")
            self.logpane.insert("end", msg + "\n")
            self.logpane.see("end")
            self.logpane.configure(state="disabled")
        self.after(100, self._poll_log)

    def _set_busy(self, busy):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.btn_scan.configure(state=state)
        self.btn_load.configure(state=state)
        self.btn_clean.configure(state=state)

    def _show_vcom(self, kind):
        VcomDialog(self, kind, self.log)

    # ------------------------------------------------------------- scanning
    def on_scan(self):
        if self.busy:
            return
        self._set_busy(True)

        def work():
            try:
                ports = read_serialcomm()
                try:
                    entities = get_pnp_entities()
                except RuntimeError as e:
                    entities = []
                    self.log(f"Warning: {e}")
                self.entities = entities
                brands = {p: b for _, p, b in entities}
                friendly = {p: nm for nm, p, _ in entities}
                rows = []
                datalogic = 0
                for name, port in sorted(ports.items(), key=lambda kv: kv[1]):
                    brand = brands.get(port)
                    rows.append((friendly.get(port, name), port, brand))
                    if brand == "datalogic":
                        datalogic += 1
                self.log_queue.put(("__rows__", rows, datalogic))
            finally:
                self.log_queue.put(("__done__",))

        threading.Thread(target=work, daemon=True).start()

    def _fill_table(self, rows, datalogic):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.ports = {}
        for name, port, brand in rows:
            self.ports[name] = port
            dl = brand == "datalogic"
            status = ("\u25cf Datalogic" if dl
                      else f"\u25cf {BRAND_LABELS.get(brand, 'Other')}")
            tag = "datalogic" if dl else "other"
            self.tree.insert("", "end", values=(name, port, status,
                                                "Load config"),
                             tags=(tag,))
        if not rows:
            self.log(" No scanner has been found, or is not connected or "
                     "is in use. Close all programs that are using this "
                     "COM-port, or connect the scanner, or put the scanner "
                     "in VCOM mode (see VCOM barcode button)")
        self.log(f"Found {len(rows)} COM port(s), "
                 f"{datalogic} Datalogic scanner(s).")

    # ------------------------------------------------------------- loading
    def _on_tree_click(self, event):
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        if self.tree.identify_column(event.x) != "#4":
            return
        vals = self.tree.item(item, "values")
        self._start_load(str(vals[0]), str(vals[1]))

    def on_load_config(self):
        if self.busy:
            return
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0], "values")
            self._start_load(str(vals[0]), str(vals[1]))
            return
        dl_rows = [i for i in self.tree.get_children()
                   if "datalogic" in self.tree.item(i, "tags")]
        if len(dl_rows) == 1:
            vals = self.tree.item(dl_rows[0], "values")
            self._start_load(str(vals[0]), str(vals[1]))
        else:
            messagebox.showinfo(
                "Load Config",
                "Selecteer een rij in de tabel "
                "(of gebruik de 'Load config' cel in een rij).")

    def _start_load(self, name, port):
        if self.busy:
            return
        brand = None
        for nm, p, b in self.entities:
            if p == port:
                brand = b
                break
        if brand is not None and brand != "datalogic":
            # Honeywell / Xenon branch of PushConfig
            self.log(f" Geen Datalogic scanner ({name} op {port}), "
                     f"dit is een {BRAND_LABELS.get(brand, 'onbekend')} "
                     f"scanner")
            honeywell_driver_check(self.log)
            self._show_vcom("honeywell")
            return
        if brand is None:
            messagebox.showwarning(
                "Onbekend apparaat",
                f"{name} op {port} is geen gekende scanner "
                "(Datalogic/Honeywell/Xenon).\n"
                "Configuratie kan alleen naar een Datalogic scanner.")
            return

        datalogic_driver_check(self.log, self)
        self._set_busy(True)

        def work():
            try:
                push_config(port, self.log, lambda ok: None)
            finally:
                self.log_queue.put(("__done__",))

        threading.Thread(target=work, daemon=True).start()

    def on_clean_ports(self):
        if self.busy:
            return
        self._set_busy(True)

        def work():
            try:
                remove_hidden_devices(self.log)
            finally:
                self.log_queue.put(("__done__",))

        threading.Thread(target=work, daemon=True).start()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
