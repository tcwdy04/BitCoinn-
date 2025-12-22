
import json
import socket
import hashlib
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ecdsa
import base58
import sys
import os
import argparse
from collections import defaultdict
from typing import Generator, Tuple, List, Optional

# ============================================================
#                     配置区域
# ============================================================
INPUT_FILE = "output.txt"
OUTPUT_BALANCES_JSON = "balances_all.json"
OUTPUT_NONZERO = "nonzero.txt"
OUTPUT_ERROR = "errors.txt"
OUTPUT_PRIVATE_KEYS = "private_keys_with_balance.txt"

ELECTRS_HOST = "127.0.0.1"
ELECTRS_PORT = 50001
SOCKET_TIMEOUT = 3
MAX_CONCURRENT_REQUESTS = 100
BATCH_SIZE = 5

# ============================================================
#                 从gen-rnd01.py导入的随机生成方法
# ============================================================

# 复制gen-rnd01.py中的相关代码
import hmac
import secrets
import random
import struct

# secp256k1 curve order (Bitcoin private keys must be in [1, n-1])
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _int_to_hex_32(i: int) -> str:
    return f"{i:064x}"


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _sample_privkey_from_int_source(get_int_256) -> int:
    # Rejection sampling for uniform distribution in [1, n-1]
    while True:
        k = get_int_256()
        if 1 <= k < SECP256K1_N:
            return k


def _sample_privkey_from_bytes_source(get_bytes_32) -> int:
    while True:
        k = _bytes_to_int(get_bytes_32())
        if 1 <= k < SECP256K1_N:
            return k


# 1) secrets.randbits (CSPRNG)
def gen1() -> str:
    priv_int = _sample_privkey_from_int_source(lambda: secrets.randbits(256))
    return _int_to_hex_32(priv_int)


# 2) secrets.token_bytes (CSPRNG)
def gen2() -> str:
    priv_int = _sample_privkey_from_bytes_source(lambda: secrets.token_bytes(32))
    return _int_to_hex_32(priv_int)


# 3) os.urandom (CSPRNG)
def gen3() -> str:
    priv_int = _sample_privkey_from_bytes_source(lambda: os.urandom(32))
    return _int_to_hex_32(priv_int)


# 4) random.SystemRandom().getrandbits (CSPRNG)
_SYSR = random.SystemRandom()


def gen4() -> str:
    priv_int = _sample_privkey_from_int_source(lambda: _SYSR.getrandbits(256))
    return _int_to_hex_32(priv_int)


# 5) SHA256(os.urandom(64)) -> 32 bytes (CSPRNG-seeded hash)
def gen5() -> str:
    def _b() -> bytes:
        return hashlib.sha256(os.urandom(64)).digest()

    priv_int = _sample_privkey_from_bytes_source(_b)
    return _int_to_hex_32(priv_int)


# 6) SHA512(os.urandom(64)) then take first 32 bytes (CSPRNG-seeded hash)
def gen6() -> str:
    def _b() -> bytes:
        return hashlib.sha512(os.urandom(64)).digest()[:32]

    priv_int = _sample_privkey_from_bytes_source(_b)
    return _int_to_hex_32(priv_int)


# 7) BLAKE2b(os.urandom(64), digest_size=32) (CSPRNG-seeded hash)
def gen7() -> str:
    def _b() -> bytes:
        return hashlib.blake2b(os.urandom(64), digest_size=32).digest()

    priv_int = _sample_privkey_from_bytes_source(_b)
    return _int_to_hex_32(priv_int)


# 8) HMAC-SHA256(key=os.urandom(32), msg=counter||os.urandom(16)) (CSPRNG-seeded MAC)
_HMAC_KEY_8 = os.urandom(32)
_HMAC_CTR_8 = 0


def gen8() -> str:
    global _HMAC_CTR_8
    _HMAC_CTR_8 += 1
    msg = struct.pack(">Q", _HMAC_CTR_8) + os.urandom(16)

    def _b() -> bytes:
        return hmac.new(_HMAC_KEY_8, msg, hashlib.sha256).digest()

    priv_int = _sample_privkey_from_bytes_source(_b)
    return _int_to_hex_32(priv_int)


# 9) HKDF-like expand with HMAC-SHA256 (CSPRNG-seeded)
_HKDF_SALT_9 = os.urandom(32)
_HKDF_IKM_9 = os.urandom(64)
_HKDF_PRK_9 = hmac.new(_HKDF_SALT_9, _HKDF_IKM_9, hashlib.sha256).digest()
_HKDF_CTR_9 = 0


def gen9() -> str:
    global _HKDF_CTR_9
    _HKDF_CTR_9 += 1
    info = b"privkey-gen-9"
    t = hmac.new(_HKDF_PRK_9, info + bytes([_HKDF_CTR_9 & 0xFF]), hashlib.sha256).digest()
    priv_int = _sample_privkey_from_bytes_source(lambda: t)
    return _int_to_hex_32(priv_int)


# 10) Deterministic stream from SHA256(seed||counter) (seeded once from CSPRNG)
_STREAM_SEED_10 = os.urandom(32)
_STREAM_CTR_10 = 0


def gen10() -> str:
    global _STREAM_CTR_10
    _STREAM_CTR_10 += 1
    b = hashlib.sha256(_STREAM_SEED_10 + struct.pack(">Q", _STREAM_CTR_10)).digest()
    priv_int = _sample_privkey_from_bytes_source(lambda: b)
    return _int_to_hex_32(priv_int)


# 所有随机生成方法的映射
RANDOM_GENERATORS = {
    1: ("secrets.randbits", gen1),
    2: ("secrets.token_bytes", gen2),
    3: ("os.urandom", gen3),
    4: ("systemrandom_getrandbits", gen4),
    5: ("sha256_urandom64", gen5),
    6: ("sha512_urandom64_first32", gen6),
    7: ("blake2b_urandom64_32", gen7),
    8: ("hmac_sha256_counter", gen8),
    9: ("hkdf_like_hmac_expand", gen9),
    10: ("sha256_seeded_counter", gen10),
}


# ============================================================
#                 简单的Electrum客户端
# ============================================================

def electrum_request_fast(method: str, params: list):
    """快速Electrum请求"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((ELECTRS_HOST, ELECTRS_PORT))

        request = json.dumps({"id": 1, "method": method, "params": params}) + "\n"
        sock.sendall(request.encode('utf-8'))

        # 接收响应
        response = b""
        start_time = time.time()

        while True:
            if time.time() - start_time > SOCKET_TIMEOUT:
                raise socket.timeout("请求超时")

            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\n' in chunk:
                    break
            except socket.timeout:
                break

        sock.close()

        if not response:
            raise ConnectionError("空响应")

        result = json.loads(response.decode('utf-8', errors='ignore'))
        if "error" in result and result["error"]:
            raise Exception(f"RPC错误: {result['error']}")

        return result.get("result", {})

    except Exception as e:
        raise Exception(f"请求失败: {e}")


# ============================================================
#                   地址生成函数
# ============================================================

def private_key_to_public_key(private_key_hex: str, compressed: bool = True):
    """私钥转公钥"""
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        curve = ecdsa.SECP256k1
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=curve)
        vk = sk.verifying_key

        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()

        if compressed:
            prefix = b'\x02' if y % 2 == 0 else b'\x03'
            return prefix + x.to_bytes(32, 'big')
        else:
            return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    except Exception as e:
        return None


def hash160(data: bytes) -> bytes:
    """计算RIPEMD160(SHA256(data))"""
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256_hash).digest()


def public_key_to_p2pkh_address(public_key: bytes) -> str:
    """P2PKH地址 (1开头)"""
    h160 = hash160(public_key)
    version = b'\x00'
    version_payload = version + h160
    checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
    return base58.b58encode(version_payload + checksum).decode()


def public_key_to_p2sh_address(public_key: bytes) -> str:
    """P2SH地址 (3开头)"""
    h160 = hash160(public_key)
    redeem_script = b'\x00\x14' + h160
    script_hash = hash160(redeem_script)
    version = b'\x05'
    version_payload = version + script_hash
    checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
    return base58.b58encode(version_payload + checksum).decode()


def generate_all_addresses_for_private_key(private_key_hex: str):
    """为单个私钥生成所有地址"""
    addresses = []

    # 压缩公钥
    compressed_pub = private_key_to_public_key(private_key_hex, compressed=True)
    if compressed_pub:
        try:
            addr = public_key_to_p2pkh_address(compressed_pub)
            addresses.append(("p2pkh_compressed", addr, compressed_pub.hex()))
        except:
            pass

        try:
            addr = public_key_to_p2sh_address(compressed_pub)
            addresses.append(("p2sh_p2wpkh_compressed", addr, compressed_pub.hex()))
        except:
            pass

    # 非压缩公钥
    uncompressed_pub = private_key_to_public_key(private_key_hex, compressed=False)
    if uncompressed_pub:
        try:
            addr = public_key_to_p2pkh_address(uncompressed_pub)
            addresses.append(("p2pkh_uncompressed", addr, uncompressed_pub.hex()))
        except:
            pass

        try:
            addr = public_key_to_p2sh_address(uncompressed_pub)
            addresses.append(("p2sh_p2wpkh_uncompressed", addr, uncompressed_pub.hex()))
        except:
            pass

    return addresses


# ============================================================
#                   余额查询函数
# ============================================================

def address_to_scripthash(addr: str) -> str:
    """地址转scripthash"""
    addr = addr.strip()

    # P2PKH (1开头)
    if addr.startswith("1"):
        decoded = base58.b58decode_check(addr)
        h160 = decoded[1:]
        script = b"\x76\xa9\x14" + h160 + b"\x88\xac"

    # P2SH (3开头)
    elif addr.startswith("3"):
        decoded = base58.b58decode_check(addr)
        h160 = decoded[1:]
        script = b"\xa9\x14" + h160 + b"\x87"

    else:
        raise ValueError(f"不支持的地址格式: {addr}")

    # SHA256 + 反转字节序
    return hashlib.sha256(script).digest()[::-1].hex()


def query_address_balance(addr: str, addr_type: str, pubkey: str):
    """查询单个地址的余额，返回完整信息"""
    try:
        scripthash = address_to_scripthash(addr)
        result = electrum_request_fast("blockchain.scripthash.get_balance", [scripthash])

        if not isinstance(result, dict):
            return {
                "address": addr,
                "address_type": addr_type,
                "total_sats": 0,
                "confirmed_sats": 0,
                "unconfirmed_sats": 0,
                "public_key": pubkey,
                "error": None
            }

        confirmed = int(result.get("confirmed", 0))
        unconfirmed = int(result.get("unconfirmed", 0))
        total = confirmed + unconfirmed

        return {
            "address": addr,
            "address_type": addr_type,
            "total_sats": total,
            "confirmed_sats": confirmed,
            "unconfirmed_sats": unconfirmed,
            "public_key": pubkey,
            "error": None
        }

    except Exception as e:
        return {
            "address": addr,
            "address_type": addr_type,
            "total_sats": 0,
            "confirmed_sats": 0,
            "unconfirmed_sats": 0,
            "public_key": pubkey,
            "error": str(e)
        }


# ============================================================
#                   批处理逻辑
# ============================================================

def process_single_private_key(key_index: int, private_key: str):
    """处理单个私钥的所有地址"""
    try:
        # 生成所有地址
        address_tuples = generate_all_addresses_for_private_key(private_key)

        if not address_tuples:
            return {
                "key_index": key_index,
                "private_key": private_key,
                "addresses": [],
                "errors": [f"无法生成地址"],
                "has_balance": False,
                "total_balance": 0
            }

        # 并发查询所有地址的余额
        results = []
        errors = []

        with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_REQUESTS, len(address_tuples))) as executor:
            # 提交所有查询任务
            futures = {}
            for addr_type, addr, pubkey in address_tuples:
                future = executor.submit(query_address_balance, addr, addr_type, pubkey)
                futures[future] = (addr_type, addr)

            # 收集结果
            for future in as_completed(futures):
                result = future.result()
                if result.get("error"):
                    errors.append(f"{result['address_type']}: {result['error']}")
                results.append(result)

        # 计算是否有余额
        has_balance = any(r["total_sats"] > 0 for r in results)
        total_balance = sum(r["total_sats"] for r in results)

        return {
            "key_index": key_index,
            "private_key": private_key,
            "addresses": results,
            "errors": errors,
            "has_balance": has_balance,
            "total_balance": total_balance
        }

    except Exception as e:
        return {
            "key_index": key_index,
            "private_key": private_key,
            "addresses": [],
            "errors": [f"处理失败: {e}"],
            "has_balance": False,
            "total_balance": 0
        }


def format_address_display(addr_type: str, addr: str, balance_sats: int):
    """格式化地址显示"""
    # 地址类型固定宽度
    type_width = 25
    type_fmt = f"{addr_type:<{type_width}}"

    # 地址显示（固定宽度44）
    addr_width = 44
    if len(addr) > addr_width:
        addr_display = addr[:20] + "..." + addr[-20:]
    else:
        addr_display = addr
    addr_fmt = f"{addr_display:<{addr_width}}"

    # 余额显示（固定宽度15，右对齐，千位分隔符）
    balance_width = 15
    balance_fmt = f"{balance_sats:>{balance_width},}".replace(",", " ")

    # BTC显示（固定宽度15，右对齐，8位小数）
    btc_width = 15
    btc = balance_sats / 1e8
    btc_fmt = f"{btc:>{btc_width}.8f}"

    # 如果有余额，前面加💰符号
    prefix = "💰 " if balance_sats > 0 else "  "

    return f"{prefix}{type_fmt} | {addr_fmt} | {balance_fmt} sats | {btc_fmt} BTC"


def parse_private_keys_from_file(filename: str, batch_size: int = BATCH_SIZE) -> Generator[
    List[Tuple[int, str]], None, None]:
    """从文件流式解析私钥，分批返回"""
    batch = []
    key_index = 0

    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                # 检查是否是私钥行 (64个十六进制字符)
                if len(line) == 64 and all(c in '0123456789abcdefABCDEF' for c in line):
                    key_index += 1
                    batch.append((key_index, line.lower()))

                    # 达到批次大小，返回批次数据
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []

            # 返回最后一批
            if batch:
                yield batch

    except Exception as e:
        print(f"❌ 解析文件失败: {e}")
        sys.exit(1)


def generate_random_private_keys(method: int, count: int, batch_size: int = BATCH_SIZE) -> Generator[
    List[Tuple[int, str]], None, None]:
    """随机生成私钥，分批返回"""
    batch = []

    if method not in RANDOM_GENERATORS:
        print(f"❌ 无效的生成方法，可选: 1-10")
        sys.exit(1)

    method_name, generator_func = RANDOM_GENERATORS[method]
    print(f"🎲 使用随机生成方法: {method_name}")

    for i in range(1, count + 1):
        private_key = generator_func()
        batch.append((i, private_key))

        # 达到批次大小，返回批次数据
        if len(batch) >= batch_size:
            yield batch
            batch = []

    # 返回最后一批
    if batch:
        yield batch


# ============================================================
#                   主处理逻辑
# ============================================================

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='比特币私钥余额查询工具')
    parser.add_argument('--mode', type=str, choices=['file', 'random'], default='file',
                        help='运行模式: file(从文件读取) 或 random(随机生成)')
    parser.add_argument('--method', type=int, choices=range(1, 11), default=1,
                        help='随机生成方法 (1-10), 仅在random模式下有效')
    parser.add_argument('--count', type=int, default=1000,
                        help='随机生成的私钥数量，仅在random模式下有效')
    parser.add_argument('--input', type=str, default=INPUT_FILE,
                        help='输入文件路径，仅在file模式下有效')
    parser.add_argument('--output-json', type=str, default=OUTPUT_BALANCES_JSON,
                        help='输出JSON文件路径')

    args = parser.parse_args()

    print("=" * 80)
    print("🚀 Bitcoin私钥余额查询工具 - 增强版")
    print("=" * 80)

    if args.mode == 'file':
        print(f"📂 模式: 从文件读取")
        print(f"  输入文件: {args.input}")
        if not os.path.exists(args.input):
            print(f"❌ 输入文件不存在: {args.input}")
            sys.exit(1)
        key_source = parse_private_keys_from_file(args.input)
        total_keys = "未知（流式读取）"
    else:
        print(f"🎲 模式: 随机生成")
        print(f"  生成方法: {args.method} ({RANDOM_GENERATORS[args.method][0]})")
        print(f"  生成数量: {args.count:,}")
        key_source = generate_random_private_keys(args.method, args.count)
        total_keys = args.count

    print(f"📊 处理规则:")
    print(f"  1. 流式处理，每批处理 {BATCH_SIZE} 个私钥")
    print(f"  2. 并发查询，最多 {MAX_CONCURRENT_REQUESTS} 个并发请求")
    print(f"  3. 每个私钥的所有地址一起显示")
    print("-" * 80)

    # 初始化统计
    start_time = time.time()
    all_results = []
    private_keys_with_balance = set()
    all_errors = []
    processed_count = 0
    total_balance = 0

    # 用于进度显示
    progress_history = []

    try:
        # 分批处理
        batch_num = 0

        for batch in key_source:
            batch_num += 1
            batch_start_time = time.time()

            print(f"\n📦 处理批次 #{batch_num} ({len(batch)} 个私钥)")

            # 并发处理当前批次中的每个私钥
            batch_results = []

            with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_REQUESTS, len(batch))) as executor:
                # 提交每个私钥的处理任务
                future_to_key = {}
                for key_index, private_key in batch:
                    future = executor.submit(process_single_private_key, key_index, private_key)
                    future_to_key[future] = (key_index, private_key)

                # 收集结果并显示
                for future in as_completed(future_to_key):
                    key_index, private_key = future_to_key[future]
                    result = future.result()

                    processed_count += 1
                    batch_results.append(result)

                    # 显示私钥的所有地址
                    print(f"\n" + "=" * 80)
                    print(f"🔑 私钥 #{key_index}: {private_key}")
                    print("-" * 80)

                    # 按地址类型排序显示
                    sorted_addresses = sorted(result["addresses"], key=lambda x: x["address_type"])

                    for addr_info in sorted_addresses:
                        display_line = format_address_display(
                            addr_info["address_type"],
                            addr_info["address"],
                            addr_info["total_sats"]
                        )
                        print(f"  {display_line}")

                    # 显示错误
                    if result["errors"]:
                        for error in result["errors"]:
                            print(f"  ❌ {error}")

                    # 如果有余额
                    if result["has_balance"]:
                        private_keys_with_balance.add(private_key)
                        total_balance += result["total_balance"]

                        # 显示发现余额的信息
                        print(f"\n  🎉 发现余额！")
                        print(f"  私钥: {private_key}")
                        print(f"  总余额: {result['total_balance']:,} sats")

                        # 显示有余额的地址详情
                        for addr_info in result["addresses"]:
                            if addr_info["total_sats"] > 0:
                                btc = addr_info["total_sats"] / 1e8
                                print(f"    {addr_info['address_type']}: {addr_info['address']}")
                                print(f"      余额: {addr_info['total_sats']:,} sats ({btc:.8f} BTC)")
                        print("-" * 80)

                    # 保存结果
                    for addr_info in result["addresses"]:
                        all_results.append({
                            "private_key": private_key,
                            "address": addr_info["address"],
                            "address_type": addr_info["address_type"],
                            "total_sats": addr_info["total_sats"],
                            "confirmed_sats": addr_info["confirmed_sats"],
                            "unconfirmed_sats": addr_info["unconfirmed_sats"],
                            "btc": addr_info["total_sats"] / 1e8,
                            "public_key": addr_info["public_key"]
                        })

                    # 收集错误
                    if result["errors"]:
                        for error in result["errors"]:
                            all_errors.append(f"私钥 #{key_index}: {error}")

            # 计算批次处理时间
            batch_time = time.time() - batch_start_time
            progress_history.append(batch_time)
            if len(progress_history) > 20:
                progress_history.pop(0)

            # 显示进度
            elapsed = time.time() - start_time
            keys_per_sec = processed_count / elapsed if elapsed > 0 else 0
            addresses_per_sec = (processed_count * 4) / elapsed if elapsed > 0 else 0

            print(f"\n📊 进度: {processed_count} 私钥 | "
                  f"{len(private_keys_with_balance)} 有余额 | "
                  f"{keys_per_sec:.1f} 密钥/秒 | "
                  f"{addresses_per_sec:.1f} 地址/秒 | "
                  f"总余额: {total_balance:,} sats | "
                  f"批次时间: {batch_time:.1f}s")

    except KeyboardInterrupt:
        print("\n⚠️ 用户中断，正在保存数据...")
    except Exception as e:
        print(f"❌ 运行错误: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # 显示最终统计
        total_time = time.time() - start_time

        print("\n" + "=" * 80)
        print("🎉 处理完成!")
        print("=" * 80)
        print(f"总处理私钥数: {processed_count}")
        print(f"有余额的私钥数: {len(private_keys_with_balance)}")
        print(f"总余额: {total_balance:,} sats ({total_balance / 1e8:.8f} BTC)")
        print(f"总耗时: {total_time:.2f} 秒")
        print(f"平均速度: {processed_count / total_time:.1f} 密钥/秒")
        print(f"错误数量: {len(all_errors)}")
        print("-" * 80)

        # 保存结果
        save_results(all_results, private_keys_with_balance, all_errors, total_time, args.output_json)


def save_results(all_results, private_keys_with_balance, errors, total_time, output_json):
    """保存结果到文件"""
    print("💾 正在保存结果...")

    # 1. 保存所有余额到JSON（按余额排序）
    try:
        all_results.sort(key=lambda x: x["total_sats"], reverse=True)

        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump({
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "processing_time": total_time,
                "total_keys": len(set(r["private_key"] for r in all_results)),
                "total_addresses": len(all_results),
                "keys_with_balance": len(private_keys_with_balance),
                "total_balance_sats": sum(r["total_sats"] for r in all_results),
                "data": all_results
            }, f, ensure_ascii=False, indent=2)

        print(f"✅ 已保存所有余额到: {output_json}")
    except Exception as e:
        print(f"❌ 保存JSON失败: {e}")

    # 2. 保存有余额的地址
    try:
        nonzero_results = [r for r in all_results if r["total_sats"] > 0]
        if nonzero_results:
            # 按私钥分组
            grouped = defaultdict(list)
            for r in nonzero_results:
                grouped[r["private_key"]].append(r)

            with open(OUTPUT_NONZERO, 'w', encoding='utf-8') as f:
                f.write(f"有余额地址报告\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"总私钥数: {len(grouped)}\n")
                f.write(f"总地址数: {len(nonzero_results)}\n")
                f.write(f"总余额: {sum(r['total_sats'] for r in nonzero_results):,} sats\n")
                f.write("=" * 80 + "\n\n")

                for private_key, addresses in grouped.items():
                    f.write(f"私钥: {private_key}\n")
                    f.write("-" * 80 + "\n")

                    for addr_info in addresses:
                        f.write(f"  {addr_info['address_type']}: {addr_info['address']}\n")
                        f.write(f"    余额: {addr_info['total_sats']:,} sats ({addr_info['btc']:.8f} BTC)\n")
                        f.write(
                            f"    确认: {addr_info['confirmed_sats']:,} | 未确认: {addr_info['unconfirmed_sats']:,}\n")
                    f.write("\n")

            print(f"✅ 已保存有余额地址到: {OUTPUT_NONZERO}")
    except Exception as e:
        print(f"❌ 保存nonzero文件失败: {e}")

    # 3. 保存有余额的私钥
    try:
        if private_keys_with_balance:
            with open(OUTPUT_PRIVATE_KEYS, 'w', encoding='utf-8') as f:
                f.write(f"有余额的私钥列表\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"总数量: {len(private_keys_with_balance)}\n")
                f.write(
                    f"总余额: {sum(r['total_sats'] for r in all_results):,} sats ({sum(r['total_sats'] for r in all_results) / 1e8:.8f} BTC)\n")
                f.write("=" * 80 + "\n")

                for pk in sorted(private_keys_with_balance):
                    f.write(f"{pk}\n")

            print(f"✅ 已保存有余额私钥到: {OUTPUT_PRIVATE_KEYS}")
            print(f"   📍 共找到 {len(private_keys_with_balance)} 个有余额的私钥")
        else:
            print("ℹ️  没有发现有余额的私钥")
    except Exception as e:
        print(f"❌ 保存私钥文件失败: {e}")

    # 4. 保存错误日志
    try:
        if errors:
            with open(OUTPUT_ERROR, 'w', encoding='utf-8') as f:
                f.write(f"错误日志\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"总错误数: {len(errors)}\n")
                f.write("=" * 80 + "\n")

                for error in errors:
                    f.write(f"{error}\n")

            print(f"✅ 已保存错误日志到: {OUTPUT_ERROR}")
    except Exception as e:
        print(f"❌ 保存错误文件失败: {e}")

    print("-" * 80)
    print("🎉 所有结果已保存完毕!")
    print("=" * 80)


if __name__ == "__main__":
    try:
        import ecdsa

        main()
    except ImportError:
        print("❌ 需要安装ecdsa库: pip install ecdsa")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 程序已停止")
        sys.exit(0)
    except Exception as e:
        print(f"❌ 程序异常: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
 