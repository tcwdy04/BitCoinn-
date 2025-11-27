import socket
import json
import hashlib
import base58
import sys
import os
import secrets
import time
import threading
import concurrent.futures
from queue import Queue, Empty
from pathlib import Path

# ===== 配置区域 =====
OUTPUT_FILE = "youyue.txt"
ELECTRS_HOST = "127.0.0.1"
ELECTRS_PORT = 50001
WIF_PREFIX = "5Jb"
ADDRESS_FILE_PATTERN = "addresses_*.txt"

# 性能配置
MAX_CONNECTIONS = 50
BATCH_SIZE = 1000
GPU_BATCH_SIZE = 10000

# 尝试导入GPU加速库
try:
    import cupy as cp
    import numpy as np

    GPU_AVAILABLE = True
    print("✅ CuPy GPU加速可用")
except ImportError:
    try:
        import torch

        GPU_AVAILABLE = True
        print("✅ PyTorch GPU加速可用")
    except ImportError:
        GPU_AVAILABLE = False
        print("❌ 未找到GPU加速库，使用CPU")


class HighPerformanceConnectionPool:
    """高性能连接池"""

    def __init__(self, host, port, max_connections=MAX_CONNECTIONS):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.connections = []
        self.connection_queue = Queue()
        self.lock = threading.Lock()
        self._initialize_connections()

    def _create_connection(self):
        """创建新连接"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((self.host, self.port))
        return sock

    def _initialize_connections(self):
        """初始化连接池"""
        print(f"🚀 初始化 {self.max_connections} 个并发连接...")
        for i in range(self.max_connections):
            try:
                sock = self._create_connection()
                self.connections.append(sock)
                self.connection_queue.put(sock)
            except Exception as e:
                print(f"❌ 连接 {i + 1} 建立失败: {e}")

        print(f"✅ 成功建立 {len(self.connections)} 个连接")

    def get_connection(self):
        """获取连接 - 带超时"""
        try:
            return self.connection_queue.get_nowait()
        except Empty:
            try:
                sock = self._create_connection()
                self.connections.append(sock)
                return sock
            except:
                # 创建失败，等待可用连接但设置超时
                try:
                    return self.connection_queue.get(timeout=5.0)  # 5秒超时
                except Empty:
                    raise RuntimeError("无法获取连接，连接池已满且创建新连接失败")

    def return_connection(self, sock):
        """归还连接"""
        try:
            # 简单测试连接是否仍然有效
            sock.send(b'')
            self.connection_queue.put_nowait(sock)
        except:
            # 连接失效，关闭并创建新的
            try:
                sock.close()
            except:
                pass
            try:
                new_sock = self._create_connection()
                self.connections.append(new_sock)
                self.connection_queue.put_nowait(new_sock)
            except:
                pass


# 全局连接池
connection_pool = HighPerformanceConnectionPool(ELECTRS_HOST, ELECTRS_PORT)


def electrs_rpc_fast(method: str, params):
    """极速版electrs通信"""
    sock = None
    try:
        sock = connection_pool.get_connection()
        sock.settimeout(10.0)  # 设置socket超时

        req = {
            "id": 1,
            "method": method,
            "params": params,
        }
        data = json.dumps(req) + "\n"

        sock.sendall(data.encode("utf-8"))

        # 使用带超时的读取
        sock.settimeout(30.0)  # 读取超时30秒
        f = sock.makefile("r", encoding="utf-8")
        line = f.readline()

        if not line:
            raise RuntimeError("No response from electrs")

        result = json.loads(line)
        connection_pool.return_connection(sock)
        return result

    except socket.timeout:
        if sock:
            try:
                sock.close()
            except:
                pass
        raise RuntimeError("electrs请求超时")
    except Exception as e:
        if sock:
            try:
                sock.close()
            except:
                pass
        raise e


def find_address_files():
    """查找所有符合模式的地址文件，并按数字排序"""
    path = Path(".")
    files = list(path.glob(ADDRESS_FILE_PATTERN))

    # 按文件名的数字部分排序
    def extract_number(filename):
        try:
            # 从 addresses_000001.txt 中提取 000001
            num_str = filename.stem.split('_')[-1]
            return int(num_str)
        except (ValueError, IndexError):
            return 0

    files.sort(key=extract_number)
    return files


def load_addresses_from_file(filename: str):
    """从文件读取地址列表"""
    path = Path(filename)
    if not path.exists():
        print(f"找不到 {filename}，请确认路径是否正确。")
        return []

    addresses = []
    seen = set()
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            addr = line.strip()
            if not addr or addr.startswith("#"):
                continue
            if addr in seen:
                continue
            seen.add(addr)
            addresses.append(addr)

    return addresses


def generate_wif_batch_cpu(batch_size=BATCH_SIZE):
    """CPU批量生成WIF"""
    wifs = []
    base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    for _ in range(batch_size):
        while True:
            try:
                private_key_bytes = secrets.token_bytes(32)
                n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                private_key_int = int.from_bytes(private_key_bytes, 'big')
                if private_key_int == 0 or private_key_int >= n:
                    continue

                wif_data = b'\x80' + private_key_bytes + b'\x01'
                checksum = hashlib.sha256(hashlib.sha256(wif_data).digest()).digest()[:4]
                full_wif_data = wif_data + checksum
                wif_string = base58.b58encode(full_wif_data).decode()

                if wif_string.startswith(WIF_PREFIX):
                    wifs.append(wif_string)
                    break
            except:
                continue

    return wifs


def generate_wif_batch_gpu(batch_size=GPU_BATCH_SIZE):
    """GPU批量生成WIF"""
    if not GPU_AVAILABLE:
        return generate_wif_batch_cpu(batch_size)

    try:
        if 'cupy' in sys.modules:
            return _generate_wif_batch_cupy(batch_size)
        elif 'torch' in sys.modules:
            return _generate_wif_batch_torch(batch_size)
        else:
            return generate_wif_batch_cpu(batch_size)
    except Exception as e:
        print(f"GPU生成失败，回退到CPU: {e}")
        return generate_wif_batch_cpu(batch_size)


def _generate_wif_batch_cupy(batch_size):
    """使用CuPy GPU加速生成WIF"""
    wifs = []

    # 生成随机私钥
    private_keys = cp.random.bytes(32 * batch_size)
    private_keys = private_keys.reshape(batch_size, 32)

    for i in range(batch_size):
        private_key_bytes = bytes(private_keys[i].get())

        # 检查私钥有效性
        private_key_int = int.from_bytes(private_key_bytes, 'big')
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if private_key_int == 0 or private_key_int >= n:
            continue

        # 构建WIF
        wif_data = b'\x80' + private_key_bytes + b'\x01'
        checksum = hashlib.sha256(hashlib.sha256(wif_data).digest()).digest()[:4]
        full_wif_data = wif_data + checksum
        wif_string = base58.b58encode(full_wif_data).decode()

        if wif_string.startswith(WIF_PREFIX):
            wifs.append(wif_string)

    return wifs


def _generate_wif_batch_torch(batch_size):
    """使用PyTorch GPU加速生成WIF"""
    wifs = []

    # 在GPU上生成随机数
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    private_keys = torch.randint(0, 256, (batch_size, 32), device=device)

    for i in range(batch_size):
        private_key_bytes = bytes(private_keys[i].cpu().numpy())

        # 检查私钥有效性
        private_key_int = int.from_bytes(private_key_bytes, 'big')
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if private_key_int == 0 or private_key_int >= n:
            continue

        # 构建WIF
        wif_data = b'\x80' + private_key_bytes + b'\x01'
        checksum = hashlib.sha256(hashlib.sha256(wif_data).digest()).digest()[:4]
        full_wif_data = wif_data + checksum
        wif_string = base58.b58encode(full_wif_data).decode()

        if wif_string.startswith(WIF_PREFIX):
            wifs.append(wif_string)

    return wifs


def wif_to_private_key(wif):
    """WIF转私钥"""
    try:
        decoded = base58.b58decode(wif)
        data = decoded[:-4]
        checksum = decoded[-4:]
        computed_checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]

        if checksum != computed_checksum:
            return None

        if len(data) != 34:
            return None

        version = data[0]
        private_key = data[1:33]
        compressed_flag = data[33]

        if version != 0x80 or compressed_flag != 0x01:
            return None

        return private_key, True
    except:
        return None


def private_key_to_public_key(private_key, compressed=True):
    """私钥转公钥"""
    try:
        import ecdsa
        sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()

        if compressed:
            x = vk.pubkey.point.x()
            y = vk.pubkey.point.y()
            prefix = b'\x02' if y % 2 == 0 else b'\x03'
            return prefix + x.to_bytes(32, 'big')
        else:
            x = vk.pubkey.point.x()
            y = vk.pubkey.point.y()
            return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    except ImportError:
        # 简化实现
        point_x = hashlib.sha256(private_key + b'x').digest()[:32]
        return b'\x02' + point_x


def hash160(data):
    """计算hash160"""
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash


def generate_address_from_wif(wif):
    """从WIF生成地址"""
    try:
        result = wif_to_private_key(wif)
        if not result:
            return None
        private_key, compressed = result

        public_key = private_key_to_public_key(private_key, compressed)
        pk_hash = hash160(public_key)

        addresses = {}
        addresses['p2pkh'] = base58.b58encode_check(b"\x00" + pk_hash).decode()

        # 只生成最常用的地址类型以加快速度
        p2wpkh_script = b"\x00\x14" + pk_hash
        p2sh_hash = hash160(p2wpkh_script)
        addresses['p2wpkh-in-p2sh'] = base58.b58encode_check(b"\x05" + p2sh_hash).decode()

        return addresses, wif
    except:
        return None


def address_to_scripthash(addr: str) -> str:
    """地址转scripthash"""
    try:
        if addr.startswith('1'):
            raw = base58.b58decode_check(addr)
            h160 = raw[1:]
            script = b"\x76\xa9\x14" + h160 + b"\x88\xac"
        elif addr.startswith('3'):
            raw = base58.b58decode_check(addr)
            h160 = raw[1:]
            script = b"\xa9\x14" + h160 + b"\x87"
        elif addr.startswith('bc1q') and len(addr) == 42:
            script = b"\x00\x14" + hash160(b"p2wpkh")
        else:
            return None

        return hashlib.sha256(script).digest()[::-1].hex()
    except:
        return None


def check_address_balance(address, addr_type="address"):
    """检查地址余额"""
    try:
        print(f"🔍 查询地址: {address}")  # 调试信息

        scripthash = address_to_scripthash(address)
        if not scripthash:
            print(f"❌ 无效地址: {address}")
            return 0, 0, 0, 0, "无效地址"

        #print(f"📡 发送请求到electrs...")  # 调试信息
        res = electrs_rpc_fast("blockchain.scripthash.get_balance", [scripthash])
        #print(f"✅ 收到响应")  # 调试信息

        if "error" in res:
            print(f"❌ electrs错误: {res['error']}")
            return 0, 0, 0, 0, f"错误: {res['error']}"

        result = res.get("result") or {}
        confirmed = int(result.get("confirmed", 0))
        unconfirmed = int(result.get("unconfirmed", 0))
        total_sats = confirmed + unconfirmed
        btc_balance = total_sats / 1e8
        if total_sats> 0:
            print(f"💰 余额结果: {total_sats} sats")  # 调试信息



        return total_sats, confirmed, unconfirmed, btc_balance, ""

    except Exception as e:
        print(f"❌ 查询异常: {e}")  # 调试信息
        return 0, 0, 0, 0, f"查询失败: {e}"


def process_address_batch(address_batch, source_info=""):
    """处理一批地址"""
    results = []

    for address in address_batch:
        total_sats, confirmed, unconfirmed, btc_balance, error = check_address_balance(address)

        if total_sats > 0:
            results.append({
                'source': source_info,
                'address': address,
                'balance': btc_balance,
                'confirmed': confirmed,
                'unconfirmed': unconfirmed
            })

    return results


def process_wif_batch(wif_batch):
    """处理一批WIF"""
    results = []

    for wif in wif_batch:
        address_result = generate_address_from_wif(wif)
        if not address_result:
            continue

        addresses, valid_wif = address_result

        for addr_type, address in addresses.items():
            total_sats, confirmed, unconfirmed, btc_balance, error = check_address_balance(address, addr_type)

            if total_sats > 0:
                results.append({
                    'wif': valid_wif,
                    'type': addr_type,
                    'address': address,
                    'balance': btc_balance,
                    'confirmed': confirmed,
                    'unconfirmed': unconfirmed
                })

    return results


def check_address_files_mode():
    """模式1：从文件读取地址并检查余额"""
    address_files = find_address_files()

    if not address_files:
        print(f"❌ 找不到符合模式 {ADDRESS_FILE_PATTERN} 的地址文件")
        return

    print(f"✅ 找到 {len(address_files)} 个地址文件:")
    for f in address_files:
        print(f"  - {f}")

    # 初始化输出文件
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("来源文件\t地址\t余额(BTC)\t已确认(sats)\t未确认(sats)\t时间\n")

    total_found = 0
    start_time = time.time()

    # 使用线程池并行处理
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONNECTIONS) as executor:
        for file_path in address_files:
            filename = str(file_path)
            print(f"\n📂 处理文件: {filename}")

            # 读取地址
            addresses = load_addresses_from_file(filename)
            if not addresses:
                print(f"  ⚠️ 文件中没有有效地址，跳过")
                continue

            print(f"  📊 共 {len(addresses)} 个地址，开始查询...")

            # 分批处理地址
            batch_size = 100
            futures = []

            for i in range(0, len(addresses), batch_size):
                batch = addresses[i:i + batch_size]
                future = executor.submit(process_address_batch, batch, filename)
                futures.append(future)

            # 收集结果
            file_found = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    results = future.result()
                    for result in results:
                        total_found += 1
                        file_found += 1

                        print(f"\n\n" + "=" * 80)
                        print("🎉🎉🎉 发现余额！ 🎉🎉🎉")
                        print(f"📁 文件: {result['source']}")
                        print(f"📍 地址: {result['address']}")
                        print(f"💰 余额: {result['balance']:.8f} BTC")
                        print("=" * 80)

                        # 保存结果
                        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                            f.write(
                                f"{result['source']}\t{result['address']}\t{result['balance']:.8f}\t{result['confirmed']}\t{result['unconfirmed']}\t{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                except Exception as e:
                    print(f"❌ 处理批次时出错: {e}")

            print(f"  ✅ 文件 {filename} 处理完成，发现 {file_found} 个有余额的地址")

    elapsed_time = time.time() - start_time
    print(f"\n🎊 所有文件处理完成！")
    print(f"📈 总共发现 {total_found} 个有余额的地址")
    print(f"⏱️ 总耗时: {elapsed_time:.2f} 秒")


def check_wif_mode():
    """模式2：随机生成WIF并检查余额"""
    print(f"🚀 开始WIF随机生成模式")
    print(f"🔑 WIF前缀: {WIF_PREFIX}")
    print(f"🎮 GPU加速: {'可用' if GPU_AVAILABLE else '不可用'}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("WIF私钥\t地址类型\t地址\t余额(BTC)\t时间\n")

    total_checked = 0
    valid_wif_count = 0
    found_count = 0
    start_time = time.time()

    # 使用线程池并行处理
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONNECTIONS) as executor:
        future_to_batch = {}
        batch_id = 0

        while True:
            batch_id += 1

            # 生成WIF批次
            if GPU_AVAILABLE:
                wif_batch = generate_wif_batch_gpu(GPU_BATCH_SIZE)
            else:
                wif_batch = generate_wif_batch_cpu(BATCH_SIZE)

            valid_wif_count += len(wif_batch)
            total_checked += len(wif_batch)

            # 提交处理任务
            future = executor.submit(process_wif_batch, wif_batch)
            future_to_batch[future] = batch_id

            # 显示进度
            elapsed_time = time.time() - start_time
            speed = valid_wif_count / elapsed_time if elapsed_time > 0 else 0

            print(f"\r🔍 批次: {batch_id} | 有效WIF: {valid_wif_count} | 速度: {speed:.1f} WIF/秒 | 发现: {found_count}",
                  end="")

            # 检查已完成的任务
            done_futures = []
            for future in list(future_to_batch.keys()):
                if future.done():
                    try:
                        results = future.result()
                        for result in results:
                            found_count += 1
                            print(f"\n\n" + "=" * 80)
                            print("🎉🎉🎉 发现余额！ 🎉🎉🎉")
                            print(f"🔑 WIF: {result['wif']}")
                            print(f"📍 {result['type']}: {result['address']}")
                            print(f"💰 余额: {result['balance']:.8f} BTC")
                            print("=" * 80)

                            # 保存结果
                            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                                f.write(
                                    f"{result['wif']}\t{result['type']}\t{result['address']}\t{result['balance']:.8f}\t{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    except Exception as e:
                        print(f"\n❌ 批次处理错误: {e}")
                    done_futures.append(future)

            # 移除已完成的任务
            for future in done_futures:
                del future_to_batch[future]

            # 控制并发数量
            while len(future_to_batch) >= MAX_CONNECTIONS * 2:
                time.sleep(0.1)


def main():
    """主函数 - 模式选择"""
    print("🚀 Bitcoin 余额查询工具")
    print("=" * 50)
    print("请选择运行模式:")
    print("1. 📁 从文件读取地址 (addresses_*.txt)")
    print("2. 🎲 随机生成WIF私钥 (5Jb开头)")
    print("3. 🚫 退出程序")

    while True:
        choice = input("\n请输入选择 (1/2/3): ").strip()

        if choice == "1":
            print("\n" + "=" * 60)
            print("📁 文件模式启动...")
            print("=" * 60)
            check_address_files_mode()
            break
        elif choice == "2":
            print("\n" + "=" * 60)
            print("🎲 WIF随机生成模式启动...")
            print("=" * 60)
            check_wif_mode()
            break
        elif choice == "3":
            print("👋 退出程序")
            return
        else:
            print("❌ 无效选择，请输入 1、2 或 3")


if __name__ == "__main__":
    main()