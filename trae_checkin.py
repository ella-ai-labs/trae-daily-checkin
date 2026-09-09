#!/usr/bin/env python3
"""Trae 每日自动签到脚本

从 TraeWork 本地 storage.json 解密认证 Token，调用签到 API 领取每日积分。
支持 Trae CN / TRAE SOLO CN / Trae SG / TRAE SOLO 四个版本。
"""

import argparse
import base64
import hashlib
import json
import platform
import sys
import urllib.request
import urllib.error
import uuid
from datetime import datetime
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
except ImportError:
    print("缺少 cryptography 库，请运行: pip install cryptography")
    sys.exit(1)

# ── Trae 版本配置 ──────────────────────────────────────────────

EDITIONS = {
    "cn": {
        "app_dir": "Trae CN",
        "api_host": "https://api.trae.cn",
        "encrypt": True,
    },
    "solo-cn": {
        "app_dir": "TRAE SOLO CN",
        "api_host": "https://api.trae.cn",
        "encrypt": True,
    },
    "sg": {
        "app_dir": "Trae",
        "api_host": "https://a0ai-api-sg.byteintlapi.com",
        "encrypt": False,
    },
    "solo-sg": {
        "app_dir": "TRAE SOLO",
        "api_host": "https://a0ai-api-sg.byteintlapi.com",
        "encrypt": True,
    },
}

# ── tc 加密常量（从 Trae JS 代码提取，社区已公开）──────────────

_IJ = bytes([
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
    124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
    84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
    8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
])
_RJ = bytes([
    31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
    96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
    160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
    23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
])
_FIXED_A = bytes(_IJ[i] ^ _RJ[i] for i in range(64))
_EXPECTED_HEADER = bytes([0x74, 0x63, 0x05, 0x10, 0x00, 0x00])

# ── API 端点 ────────────────────────────────────────────────────

STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"
REFRESH_PATH = "/trae/api/v2/ug/user/refresh_token"

# ── 运行环境自动检测 ───────────────────────────────────────────

_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _detect_device_type() -> str:
    system = platform.system()
    if system == "Darwin":
        return "mac"
    elif system == "Windows":
        return "windows"
    return "linux"


def _detect_os_version() -> str:
    system = platform.system()
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0]}"
    elif system == "Windows":
        return f"Windows {platform.release()}"
    return f"{system} {platform.release()}"


def _get_storage_path(app_dir: str) -> Path:
    home = Path.home()
    system = platform.system()
    if system == "Darwin":
        return home / "Library" / "Application Support" / app_dir / "User" / "globalStorage" / "storage.json"
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        return appdata / app_dir / "User" / "globalStorage" / "storage.json"
    return home / ".config" / app_dir / "User" / "globalStorage" / "storage.json"


# ── tc 加密解密 ─────────────────────────────────────────────────

def _derive_key_iv(enc_key: bytes) -> tuple[bytes, bytes]:
    h1 = hashlib.sha512(enc_key).digest()
    concat = h1 + _FIXED_A
    h2 = hashlib.sha512(concat).digest()
    return h2[:16], h2[16:32]


def decrypt_auth(encrypted_b64: str) -> dict:
    enc_data = base64.b64decode(encrypted_b64)
    if len(enc_data) < 38:
        raise ValueError("密文太短")
    if enc_data[:6] != _EXPECTED_HEADER:
        try:
            return json.loads(encrypted_b64)
        except json.JSONDecodeError:
            raise ValueError("无效的加密头部，也不是明文 JSON")
    enc_key = enc_data[6:38]
    ciphertext = enc_data[38:]
    aes_key, iv = _derive_key_iv(enc_key)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted) + unpadder.finalize()
    stored_hash = decrypted[:64]
    plain = decrypted[64:]
    computed_hash = hashlib.sha512(plain).digest()
    if stored_hash != computed_hash:
        raise ValueError("哈希校验失败")
    return json.loads(plain.decode("utf-8"))


# ── 认证 & API 调用 ─────────────────────────────────────────────

def read_auth(edition: str) -> dict:
    config = EDITIONS[edition]
    storage_path = _get_storage_path(config["app_dir"])
    with open(storage_path, "r") as f:
        data = json.load(f)
    auth_b64 = data.get("iCubeAuthInfo://icube.cloudide")
    if not auth_b64:
        raise ValueError(f"{storage_path} 中未找到 iCubeAuthInfo://icube.cloudide")
    if config["encrypt"]:
        return decrypt_auth(auth_b64)
    return json.loads(auth_b64)


def build_headers(token: str, user_id: str) -> dict:
    machine_id = uuid.uuid4().hex + uuid.uuid4().hex
    device_id = hashlib.sha256(machine_id.encode()).hexdigest()[:32]
    return {
        "Content-Type": "application/json",
        "Authorization": f"Cloud-IDE-JWT {token}",
        "X-Cloudide-Token": token,
        "x-uid": str(user_id),
        "x-app-id": "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8",
        "x-device-id": device_id,
        "x-machine-id": machine_id,
        "x-request-id": str(uuid.uuid4()),
        "x-ide-version": "3.3.67",
        "x-ide-version-code": "20260401",
        "x-device-type": _detect_device_type(),
        "x-os-version": _detect_os_version(),
    }


def api_call(base_url: str, path: str, token: str, user_id: str) -> dict:
    url = base_url + path
    body = json.dumps({"userId": str(user_id)}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers=build_headers(token, user_id),
        method="POST",
    )
    try:
        with _NO_PROXY_OPENER.open(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="ignore")
        return {"error": f"HTTP {e.code}", "detail": error_body}
    except Exception as e:
        return {"error": str(e)}


def refresh_token(base_url: str, refresh: str, user_id: str) -> dict:
    url = base_url + REFRESH_PATH
    body = json.dumps({"refreshToken": refresh, "userId": str(user_id)}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _NO_PROXY_OPENER.open(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"Token 刷新失败: HTTP {e.code}")
        return {}
    except Exception as e:
        print(f"Token 刷新出错: {e}")
        return {}


# ── 主流程 ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Trae 每日自动签到")
    parser.add_argument(
        "-e", "--edition",
        choices=list(EDITIONS.keys()),
        default="solo-cn",
        help="Trae 版本 (默认: solo-cn)",
    )
    parser.add_argument(
        "--log", default=str(Path.home() / ".trae_checkin.log"),
        help="日志文件路径",
    )
    args = parser.parse_args()

    config = EDITIONS[args.edition]
    base_url = config["api_host"]
    log_path = Path(args.log)

    def log(msg):
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
        print(line)
        with open(log_path, "a") as f:
            f.write(line + "\n")

    try:
        auth = read_auth(args.edition)
    except FileNotFoundError:
        log(f"未找到 storage.json，请确认已安装并登录 TraeWork")
        sys.exit(1)
    except Exception as e:
        log(f"读取认证信息失败: {e}")
        sys.exit(1)

    token = auth.get("token") or auth.get("accessToken")
    refresh = auth.get("refreshToken")
    user_id = auth.get("userId") or auth.get("uid")

    if not token or not user_id:
        log(f"认证信息中缺少 token 或 userId，可用字段: {list(auth.keys())}")
        sys.exit(1)

    result = api_call(base_url, STATUS_PATH, token, user_id)
    if "error" in result:
        if "401" in str(result.get("error", "")) and refresh:
            log("Token 已过期，尝试刷新...")
            refreshed = refresh_token(base_url, refresh, user_id)
            if refreshed:
                new_token = refreshed.get("token") or refreshed.get("accessToken")
                if new_token:
                    token = new_token
                    log("Token 刷新成功，重新检查签到状态")
                    result = api_call(base_url, STATUS_PATH, token, user_id)
                else:
                    log(f"Token 刷新返回中无 token 字段: {list(refreshed.keys())}")
            else:
                log("Token 刷新失败，请重新打开 TraeWork 登录")
                sys.exit(1)
        else:
            log(f"查询签到状态失败: {result}")
            sys.exit(1)

    code = result.get("code")
    if code != 0:
        log(f"查询签到状态失败: code={code}, msg={result.get('message')}")
        sys.exit(1)

    already_checked = result.get("checked_in", False)
    credits = result.get("credits", 0)
    extra = result.get("extra_credits", 0)
    extra_str = f"（含额外 {extra}）" if extra else ""

    if already_checked:
        log(f"今日已签到，当前积分: {credits}{extra_str}")
        sys.exit(0)

    log("今日尚未签到，正在领取积分...")
    claim_result = api_call(base_url, CLAIM_PATH, token, user_id)
    if "error" in claim_result:
        log(f"领取积分失败: {claim_result}")
        sys.exit(1)

    claim_code = claim_result.get("code")
    if claim_code != 0:
        log(f"领取积分失败: code={claim_code}, msg={claim_result.get('message')}")
        sys.exit(1)

    log(f"签到成功！当前积分: {credits}{extra_str}")


if __name__ == "__main__":
    main()
