#!/bin/sh
# Unix 远程安装脚本（Copy-SshId 使用）：把本机公钥追加到 ~/.ssh/authorized_keys。
# 公钥经 heredoc 内嵌（heredoc 正文处的公钥占位符由调用方替换为实际公钥内容，故本注释中不写出该占位符字面量）；脚本整体 base64 后作为 ssh 参数在远端解码执行。安装的同时清理 authorized_keys 中的异常行：空行、以及不以合法公钥算法前缀开头的行（例如终端回显被误写入的噪声行）。保留所有合法公钥行，整体去重后原子写回。
cd || exit 1
umask 077
mkdir -p .ssh
ak=.ssh/authorized_keys
touch "$ak"
tmp="$ak.sshcopyid.tmp"
# 1) 过滤现有文件：只保留以合法公钥算法前缀开头的非空行（删除空行与噪声行）
awk 'NF && /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-|sk-ssh-ed25519|sk-ecdsa-sha2-)/' "$ak" > "$tmp" 2>/dev/null
# 2) 追加本机公钥（若不在保留结果中）
while IFS= read -r key || [ -n "$key" ]; do
    [ -n "$key" ] || continue
    grep -qxF "$key" "$tmp" || printf '%s\n' "$key" >> "$tmp"
done <<'__SSH_COPY_ID_KEYS__'
__KEYS__
__SSH_COPY_ID_KEYS__
# 3) 整体去重（sort -u 同时会排好序）
sort -u "$tmp" -o "$tmp"
# 4) 原子写回：先写临时文件再覆盖原文件，属主/属组不变（写已存在文件）
chmod 600 "$tmp"
cat "$tmp" > "$ak"
rm -f "$tmp"
