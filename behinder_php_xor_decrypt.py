#!/usr/bin/env python3
"""
冰蝎 (Behinder) PHP-Xor-Request 解密/加密工具
==============================================
从 BlueTeamToolsV1.32.jar 的 godzilla.cryptions.php.PhpXorBase64 提取

算法:
  1. Key = MD5(password)[:16]
  2. 解密: base64_decode(data) → XOR each byte with key[(i+1) & 15]
  3. 加密: XOR each byte with key[(i+1) & 15] → base64_encode

请求格式 (Legacy PHP):
  加密前: func|params  (如: assert|eval(base64_decode('...')))
  加密后: base64(XOR(plaintext))

响应格式:
  加密前: JSON {"status":"base64(success)","msg":"base64(content)"}
  加密后: base64(XOR(json))

用法:
  # 解密请求
  python3 behinder_php_xor_decrypt.py -d -k rebeyond -i <base64密文>
  python3 behinder_php_xor_decrypt.py -d -k rebeyond -f request.bin

  # 加密响应
  python3 behinder_php_xor_decrypt.py -e -k rebeyond -i '{"status":"c3VjY2Vzcw==","msg":"dGVzdA=="}'

  # 从 pcap 提取并解密 (需要 scapy)
  python3 behinder_php_xor_decrypt.py -p capture.pcap -k rebeyond

  # 交互模式
  python3 behinder_php_xor_decrypt.py -k rebeyond
"""

import argparse
import base64
import hashlib
import json
import sys


def derive_key(password: str) -> str:
    """MD5(password)[:16]"""
    return hashlib.md5(password.encode()).hexdigest()[:16]


def xor_decrypt(data: bytes, key: str) -> bytes:
    """XOR 解密: data[i] ^ key[(i+1) & 15]"""
    key_bytes = key.encode()
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key_bytes[(i + 1) & 15]
    return bytes(result)


def xor_encrypt(data: bytes, key: str) -> bytes:
    """XOR 加密 (与解密算法相同, XOR 是对称的)"""
    return xor_decrypt(data, key)


def decrypt_request(raw: bytes, key: str) -> str:
    """
    解密冰蝎 PHP-Xor-Request
    输入: base64 编码的 XOR 密文 (原始 HTTP body)
    输出: 明文字符串 (func|params 格式)
    """
    # base64 解码
    decoded = base64.b64decode(raw)
    # XOR 解密
    plain = xor_decrypt(decoded, key)
    return plain.decode('utf-8', errors='replace')


def encrypt_response(plain: str, key: str) -> str:
    """
    加密响应
    输入: JSON 字符串
    输出: base64(XOR(plaintext))
    """
    data = plain.encode('utf-8')
    encrypted = xor_encrypt(data, key)
    return base64.b64encode(encrypted).decode('ascii')


def decrypt_response(raw: bytes, key: str) -> dict:
    """
    解密冰蝎响应
    输入: base64 编码的 XOR 密文
    输出: 解析后的 JSON dict (值已 base64 解码)
    """
    plain = decrypt_request(raw, key)
    try:
        data = json.loads(plain)
        # 解码所有 base64 编码的值
        result = {}
        for k, v in data.items():
            try:
                result[k] = base64.b64decode(v).decode('utf-8', errors='replace')
            except Exception:
                result[k] = v
        return result
    except json.JSONDecodeError:
        return {"raw": plain}


def parse_legacy_payload(plain: str) -> dict:
    """
    解析 Legacy PHP shell 的 func|params 格式
    """
    parts = plain.split('|', 1)
    result = {
        "func": parts[0],
        "params": parts[1] if len(parts) > 1 else "",
    }

    # 尝试解码 eval(base64_decode('...')) 中的 base64 内容
    import re
    m = re.search(r"base64_decode\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", result["params"])
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
            result["decoded_payload"] = decoded
        except Exception:
            pass

    return result


def parse_aes_payload(plain: str) -> dict:
    """
    解析 default_aes 协议的 PHP 代码格式
    """
    import re
    result = {"raw": plain}

    # 检测动作类型
    if "getInnerIP" in plain or "basicInfoObj" in plain:
        result["action"] = "BasicInfo"
    elif "proc_open" in plain and "pty" in plain:
        result["action"] = "RealCmd"
    elif re.search(r"(system|passthru|shell_exec|exec)\s*\(", plain):
        result["action"] = "Cmd"
    elif "function main($content)" in plain or "function main( $content)" in plain:
        result["action"] = "Echo"
    elif re.search(r"(mysqli_connect|mysql_connect|PDO)\s*\(", plain):
        result["action"] = "Database"
    elif re.search(r"(file_get_contents|file_put_contents|readfile|fopen|unlink)\s*\(", plain):
        result["action"] = "FileOperation"
    else:
        result["action"] = "Unknown"

    # 提取 echo 内容
    if result["action"] == "Echo":
        m = re.search(r'\$content\s*=\s*["\']([A-Za-z0-9+/=]+)["\']', plain)
        if m:
            try:
                result["echo_content"] = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
            except Exception:
                pass

    # 提取命令
    if result["action"] in ("Cmd", "RealCmd"):
        m = re.search(r"main\s*\(\s*['\"]([^'\"]*)['\"]\s*\)", plain)
        if m:
            result["command"] = m.group(1)

    return result


def process_pcap(pcap_file: str, key: str):
    """
    从 pcap 文件提取并解密冰蝎流量
    """
    try:
        from scapy.all import sniff, TCPSession
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    except ImportError:
        print("[!] 需要 scapy: pip install scapy")
        return

    print(f"[*] 读取 pcap: {pcap_file}")
    print(f"[*] Key: {key}")
    print()

    pkts = sniff(offline=pcap_file, session=TCPSession)

    requests = {}  # keyed by TCP ack number
    for pkt in pkts:
        try:
            if pkt.haslayer(HTTPRequest):
                raw = pkt[HTTPRequest].payload.load
                tag = str(pkt['IP'].ack)
                requests[tag] = ("request", raw)
            elif pkt.haslayer(HTTPResponse):
                raw = pkt[HTTPResponse].payload.load
                tag = str(pkt['IP'].ack)
                if tag in requests:
                    requests[tag] = (requests[tag][0], requests[tag][1] + raw)
                else:
                    requests[tag] = ("response", raw)
        except Exception:
            continue

    print(f"[*] 找到 {len(requests)} 个 HTTP 流")
    print()

    for tag, (msg_type, raw) in requests.items():
        print(f"{'='*60}")
        print(f"  TCP ACK: {tag}")
        print(f"  类型: {msg_type}")
        print(f"  大小: {len(raw)} bytes")

        try:
            plain = decrypt_request(raw, key)
            print(f"  解密: {len(plain)} bytes")

            if msg_type == "request":
                if '|' in plain:
                    info = parse_legacy_payload(plain)
                    print(f"  协议: Legacy")
                    print(f"  函数: {info['func']}")
                    if "decoded_payload" in info:
                        print(f"  解码内容:")
                        for line in info["decoded_payload"].split('\n')[:20]:
                            print(f"    {line}")
                    else:
                        print(f"  参数: {info['params'][:200]}")
                else:
                    info = parse_aes_payload(plain)
                    print(f"  协议: default_aes")
                    print(f"  动作: {info['action']}")
                    if "echo_content" in info:
                        print(f"  Echo: {info['echo_content']}")
                    if "command" in info:
                        print(f"  命令: {info['command']}")
            else:
                result = decrypt_response(raw, key)
                print(f"  响应JSON: {json.dumps(result, ensure_ascii=False, indent=2)}")

        except Exception as e:
            print(f"  [!] 解密失败: {e}")

        print()


def interactive_mode(key: str):
    """交互模式"""
    print(f"[*] 冰蝎 PHP-Xor-Request 交互解密")
    print(f"[*] Key: {key}")
    print(f"[*] 输入 'q' 退出, 'e' 加密, 'd' 解密")
    print()

    while True:
        try:
            mode = input("[d/e/q] > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if mode == 'q':
            break
        elif mode == 'e':
            plain = input("明文 > ")
            enc = encrypt_response(plain, key)
            print(f"密文: {enc}")
            print()
        elif mode == 'd':
            raw = input("密文 (base64) > ").strip()
            try:
                plain = decrypt_request(raw.encode(), key)
                print(f"明文 ({len(plain)} bytes):")
                if '|' in plain:
                    info = parse_legacy_payload(plain)
                    print(f"  协议: Legacy")
                    print(f"  函数: {info['func']}")
                    if "decoded_payload" in info:
                        print(f"  解码内容:")
                        for line in info["decoded_payload"].split('\n')[:30]:
                            print(f"    {line}")
                    else:
                        print(f"  参数: {info['params'][:500]}")
                else:
                    info = parse_aes_payload(plain)
                    print(f"  协议: default_aes")
                    print(f"  动作: {info['action']}")
                    if "echo_content" in info:
                        print(f"  Echo: {info['echo_content']}")
                    if "command" in info:
                        print(f"  命令: {info['command']}")
                    print(f"  原始: {plain[:500]}")
                print()
            except Exception as e:
                print(f"[!] 解密失败: {e}")
                print()
        else:
            # 直接输入密文
            try:
                plain = decrypt_request(mode.encode(), key)
                print(f"明文: {plain[:500]}")
                print()
            except Exception:
                print("[!] 无效输入")


def main():
    parser = argparse.ArgumentParser(
        description="冰蝎 PHP-Xor-Request 解密/加密工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 解密请求
  %(prog)s -d -k rebeyond -i "VnVHOVpUbDJ5dTVzVkJjaWJNVUtUMzBL..."

  # 加密响应
  %(prog)s -e -k rebeyond -i '{"status":"c3VjY2Vzcw==","msg":"dGVzdA=="}'

  # 从 pcap 解密
  %(prog)s -p capture.pcap -k rebeyond

  # 从文件解密
  %(prog)s -d -k rebeyond -f request.bin

  # 交互模式
  %(prog)s -k rebeyond
        """
    )
    parser.add_argument('-d', '--decrypt', action='store_true', help='解密模式')
    parser.add_argument('-e', '--encrypt', action='store_true', help='加密模式')
    parser.add_argument('-k', '--key', default='rebeyond', help='连接密码 (默认: rebeyond)')
    parser.add_argument('-i', '--input', help='输入数据 (base64 字符串)')
    parser.add_argument('-f', '--file', help='输入文件')
    parser.add_argument('-p', '--pcap', help='pcap 文件路径')
    parser.add_argument('--raw-key', help='直接使用原始 key (16字节hex), 不做 MD5')

    args = parser.parse_args()

    # 派生 key
    if args.raw_key:
        key = args.raw_key
    else:
        key = derive_key(args.key)

    # pcap 模式
    if args.pcap:
        process_pcap(args.pcap, key)
        return

    # 解密模式
    if args.decrypt:
        if args.input:
            raw = args.input.encode()
        elif args.file:
            with open(args.file, 'rb') as f:
                raw = f.read()
        else:
            print("[!] 需要 -i 或 -f 参数")
            return

        try:
            plain = decrypt_request(raw, key)
            print(f"[+] 解密成功 ({len(plain)} bytes)")
            print()

            if '|' in plain:
                info = parse_legacy_payload(plain)
                print(f"协议: Legacy")
                print(f"函数: {info['func']}")
                print(f"参数: {info['params'][:200]}")
                if "decoded_payload" in info:
                    print()
                    print("解码内容:")
                    print(info["decoded_payload"])
            else:
                info = parse_aes_payload(plain)
                print(f"协议: default_aes")
                print(f"动作: {info['action']}")
                if "echo_content" in info:
                    print(f"Echo: {info['echo_content']}")
                if "command" in info:
                    print(f"命令: {info['command']}")
                print()
                print("原始内容:")
                print(plain)
        except Exception as e:
            print(f"[!] 解密失败: {e}")
        return

    # 加密模式
    if args.encrypt:
        if args.input:
            plain = args.input
        elif args.file:
            with open(args.file, 'r') as f:
                plain = f.read()
        else:
            print("[!] 需要 -i 或 -f 参数")
            return

        enc = encrypt_response(plain, key)
        print(f"[+] 加密成功 ({len(enc)} bytes)")
        print(enc)
        return

    # 交互模式
    interactive_mode(key)


if __name__ == "__main__":
    main()
