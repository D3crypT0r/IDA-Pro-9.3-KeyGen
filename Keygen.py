import sys

def silent_pip_install(package):
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def require(modulename, packagename=None):
    import importlib
    try:
        return importlib.import_module(modulename)
    except ImportError:
        silent_pip_install(packagename if packagename else modulename)
        return importlib.import_module(modulename)

json = require("json")
os = require("os")
hashlib = require("hashlib")
shutil = require("shutil")
ctypes = require("ctypes")
re = require("re")

def is_admin():
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return False

def capitalize_words(s):
    return ' '.join(word.capitalize() for word in s.split())

if os.name == 'nt':
    if not is_admin():
        print(capitalize_words("[*] restarting script with administrator privileges ..."))
        script = sys.argv[0]
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit(0)

product_version_str = "9.3"
start_date_str = "2026-01-01 00:00:00"
end_date_str = "2099-12-31 23:59:59"

license = {
    "header": {"version": 1},
    "payload": {
        "name": "ProxyBar [ https://t.me/proxy_bar ]",
        "email": "1@1.ru",
        "licenses": [
            {
                "description": "Licensed to: proxy_bar",
                "edition_id": "ida-pro",
                "id": "FF-FFFF-FFFF-FF",
                "license_type": "named",
                "product": "IDA",
                "seats": 1337,
                "start_date": start_date_str,
                "end_date": end_date_str,
                "issued_on": start_date_str,
                "owner": "ProxyBar [ https://t.me/proxy_bar ]",
                "product_id": "IDAPRO",
                "product_version": product_version_str,
                "add_ons": [],
                "features": [],
            }
        ],
    },
}

def addons(license_obj):
    addons_list = [
        "LUMINA", "PRIVATE_LUMINA", "TEAMS", "HEXX86", "HEXX64", "HEXARM", "HEXARM64", "HEXMIPS", "HEXMIPS64", "HEXPPC", "HEXPPC64", "HEXRV", "HEXRV64", "HEXARC", "HEXARC64", "HEXV850", "HEXSH", "HEXRH850", "HEX68K", "HEX68330", "HEXHC08", "HEXHC11", "HEXHC12", "HEX9S12", "HEX8051", "HEXMCS96", "HEXI960", "HEXZ80", "HEXTMS320C1", "HEXTMS320C3", "HEXTMS320C5", "HEXTMS320C6", "HEXNEC78K0", "HEXNEC78K0S", "HEXNECV850", "HEXPIC12", "HEXPIC16", "HEXPIC18", "HEXPIC24", "HEXPIC30", "HEXPIC33", "HEXAVR", "HEXH8", "HEXH8500", "HEXSTM8", "HEXM32R", "HEXM16C", "HEXC166", "HEXEBC", "HEXCR16", "HEXM7900", "HEXM7700", "HEXSPARC", "HEXALPHA",
    ]
    for addon in addons_list:
        license_obj["payload"]["licenses"][0]["add_ons"].append({
            "id": "FF-FFFF-FFFF-FF",
            "code": addon,
            "owner": license_obj["payload"]["licenses"][0]["id"],
            "start_date": "2026-01-01 00:00:00",
            "end_date": "2099-12-31 23:59:59"
        })
addons(license)

def sort(obj):
    if isinstance(obj, list):
        return "[" + ",".join([sort(x) for x in obj]) + "]"
    elif isinstance(obj, dict):
        items = []
        for k in sorted(obj.keys()):
            items.append(f'"{k}":' + sort(obj[k]))
        return "{" + ",".join(items) + "}"
    else:
        return json.dumps(obj)

cModulus = bytes.fromhex(
    "edfd42cbf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f"
    "4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5ddd"
    "d91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e3"
    "3c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93"
)

privateKey = bytes.fromhex(
    "77c86abbb7f3bb134436797b68ff47beb1a5457816608dbfb72641814dd464dd"
    "640d711d5732d3017a1c4e63d835822f00a4eab619a2c4791cf33f9f57f9c2ae"
    "4d9eed9981e79ac9b8f8a411f68f25b9f0c05d04d11e22a3a0d8d4672b56a61f"
    "1532282ff4e4e74759e832b70e98b9d102d07e9fb9ba8d15810b144970029874"
)

def encrypt(message_bytes):
    modulusBuf = 0
    for i in range(len(cModulus) - 1, -1, -1):
        modulusBuf = (modulusBuf << 8) + cModulus[i]
    keyBuf = 0
    for i in range(len(privateKey) - 1, -1, -1):
        keyBuf = (keyBuf << 8) + privateKey[i]
    reversed_bytes = bytearray(message_bytes)[::-1]
    msgBuf = 0
    for i in range(len(reversed_bytes) - 1, -1, -1):
        msgBuf = (msgBuf << 8) + reversed_bytes[i]
    base = msgBuf % modulusBuf
    exponent = keyBuf
    modulus = modulusBuf
    encryptedBigInt = 1
    while exponent > 0:
        if exponent % 2 == 1:
            encryptedBigInt = (encryptedBigInt * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    bytes_out = []
    buffer = encryptedBigInt
    while buffer > 0:
        bytes_out.append(buffer & 0xFF)
        buffer >>= 8
    return bytes(bytes_out)

def patch(file_path, search: bytes, replace: bytes):
    try:
        with open(file_path, "rb") as fp:
            buf = bytearray(fp.read())
        idx = buf.find(search)
        if idx != -1:
            buf[idx:idx+len(replace)] = replace
            with open(file_path, "wb") as fp:
                fp.write(buf)
            print(capitalize_words(f"patched successfully to : ({file_path})"))
            return
        else:
            print(capitalize_words(f"pattern not found in {file_path}"))
            return
    except Exception as err:
        print(capitalize_words(f"error reading or writing file: {file_path}"))
        print(capitalize_words("elevated permissions given?"))
        return

def sign(payload):
    data = {"payload": payload}
    dataStr = sort(data)
    buffer = bytearray([0x42] * 33 + [0] * (128 - 33))
    h = hashlib.sha256()
    h.update(dataStr.encode("utf-8"))
    digest = h.digest()
    buffer[33:33+len(digest)] = digest
    encrypted = encrypt(buffer)
    return encrypted.hex().upper()

license["signature"] = sign(license["payload"])

with open("idapro.hexlic", "w") as f:
    f.write(sort(license))
print(capitalize_words("license written to idapro.hexlic"))

try:
    appdata = os.environ.get('APPDATA')
    if appdata:
        hexrays_dir = os.path.join(appdata, 'Hex-Rays', 'Ida Pro')
        os.makedirs(hexrays_dir, exist_ok=True)
        shutil.copy("idapro.hexlic", os.path.join(hexrays_dir, "idapro.hexlic"))
        print(capitalize_words(f"copied idapro.hexlic to {hexrays_dir}"))
    else:
        print(capitalize_words("appdata environment variable not found, cannot copy license file!"))
except Exception as e:
    print(capitalize_words(f"error copying idapro.hexlic to %appdata%: {e}"))

if os.name == 'nt':
    winreg = require("winreg")
    def update_ida_license_registry():
        reg_path = r"SOFTWARE\Hex-Rays\IDA\Licenses"
        license_key_pattern = re.compile(r"^IDAPRO\.ida-pro\..*")
        value_name = "0"

        appdata_dir = os.path.expandvars(r"%APPDATA%\Hex-Rays\Ida Pro")
        new_lic_path = os.path.join(appdata_dir, "idapro.hexlic")
        license_dict = {
            "licsrc": {"path": new_lic_path},
            "lid": "FF-FFFF-FFFF-FF"
        }
        license_json = json.dumps(license_dict)

        roots = [
            (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
        ]

        updated_any = False

        for root, root_name in roots:
            try:
                with winreg.OpenKey(root, reg_path, 0, winreg.KEY_ALL_ACCESS) as licenses_key:
                    subkey_count, _, _ = winreg.QueryInfoKey(licenses_key)
                    updated = False
                    for i in range(subkey_count):
                        subkey_name = winreg.EnumKey(licenses_key, i)
                        if license_key_pattern.match(subkey_name):
                            try:
                                with winreg.OpenKey(licenses_key, subkey_name, 0, winreg.KEY_ALL_ACCESS) as license_key:
                                    winreg.SetValueEx(license_key, value_name, 0, winreg.REG_SZ, license_json)
                                    print(capitalize_words(f"updated registry license value at {root_name}\\{reg_path}\\{subkey_name}"))
                                    updated = True
                                    updated_any = True
                            except FileNotFoundError:
                                continue
                    if not updated:
                        print(capitalize_words(f"no matching license subkey found in {root_name}\\{reg_path}"))
            except PermissionError as pe:
                print(capitalize_words(f"permission denied trying to open {root_name}\\{reg_path}: {pe}"))
            except FileNotFoundError:
                print(capitalize_words(f"registry path not found: {root_name}\\{reg_path}"))
            except Exception as e:
                print(capitalize_words(f"error accessing the registry at {root_name}\\{reg_path}: {e}"))

        if not updated_any:
            print(capitalize_words("no registry license key updated. try running the script as administrator."))
    update_ida_license_registry()

    search = bytes.fromhex("EDFD425CF978")
    replace = bytes.fromhex("EDFD42CBF978")

    def get_ida_pro_path():
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Hex-Rays\IDA") as key:
                value, _ = winreg.QueryValueEx(key, "InputDirectory")
                return value
        except Exception as e:
            print(capitalize_words(f"could not get 'ida pro path' from registry: {e}"))
            return None

    ida_pro_path = get_ida_pro_path()
    if ida_pro_path is not None:
        dll_files = [
            "ida.dll", "ida32.dll"
        ]
        for file in dll_files:
            file_path = os.path.join(ida_pro_path, file)
            if os.path.exists(file_path):
                patch(file_path, search, replace)
    else:
        print(capitalize_words("ida pro path not found in registry. patch not applied to dll files."))
else:
    search = bytes.fromhex("EDFD425CF978")
    replace = bytes.fromhex("EDFD42CBF978")

    other_files = [
        "libida.so", "libida32.so", "libida.dylib", "libida32.dylib"
    ]
    current_dir = os.path.abspath(os.path.dirname(__file__))
    for file in other_files:
        file_path = os.path.join(current_dir, file)
        if os.path.exists(file_path):
            print(capitalize_words(f"patch applied successfully to : ({file_path})"))
            patch(file_path, search, replace)
