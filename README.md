如果你希望研究比特币的私钥，第一步就是要拥有全节点钱包，并想办法提取它所有的信息，然后针对这些信息，去反向研究。这是基础。
<img width="1108" height="480" alt="image" src="https://github.com/user-attachments/assets/54cd0108-11ae-49>

# BitCoinn-
BitCoinn内核查询余额,Python + Ubuntu

第一步下载Ubuntu
powshell (管理员执行）
wsl --install -d Ubuntu


第二步ubuntu执行更新安装相关库
sudo apt update
sudo apt install -y git build-essential clang cmake pkg-config libssl-dev librocksdb-dev
sudo apt install -y llvm-dev libclang-dev clang

3、安装RUST
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# 安装过程中 按回车
source ~/.cargo/env

4、下载electrs，下载不了可以直接下载到本地
cd ~
git clone https://github.com/romanz/electrs.git
cd electrs
cargo build --release

5、找到ELE文 （假设在D/electrs目录）
cp -r /mnt/d/electrs ~/electrs

6、复制ELE文件到根目录 开始编译
cp -r /mnt/d/electrs ~/electrs
cd electrs
cargo build --release

7、删除原来的ele配置
rm ~/.electrs/config.toml

8、新建ele配置文件
nano ~/.electrs/config.toml

9、粘贴下面配置文件到config.toml
#-------------------------------
# Electrs 配置文件 (最终正确版本)
network = "bitcoin"
# Bitcoin Core 节点配置
daemon_dir = "/mnt/d/data"
daemon_rpc_addr = "127.0.0.1:8332"
daemon_p2p_addr = "127.0.0.1:8333"
cookie_file = "/mnt/d/data/.cookie"

# Electrum RPC 服务端口（注意：不要加 jsonrpc_import）
electrum_rpc_addr = "0.0.0.0:50001"

# 本地数据库目录
db_dir = "/home/user/.electrs/db"

# 日志与性能
log_filters = "INFO"
jsonrpc_timeout = 30
#----------------------------------------

Ctrl + O → 回车保存
Ctrl + X 退出 

10、启动ele服务
ulimit -n 65535
cd ~/electrs
./target/release/electrs --conf ~/.electrs/config.toml


# 管理员cmd 定义端口流量限制
netsh int ipv4 set dynamicport tcp start=10000 num=55000
netsh int ipv6 set dynamicport tcp start=10000 num=55000

# BITCOIn核心CONFIG
去掉用户名和密码
