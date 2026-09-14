#!/bin/sh
# Unix 远程移除脚本（Remove-SshId 使用）：从 ~/.ssh/authorized_keys 中删除与本机公钥完全匹配的行。
# 公钥经 heredoc 内嵌（heredoc 正文处的公钥占位符由调用方替换为实际公钥内容，故本注释中不写出该占位符字面量）；脚本整体 base64 后作为 ssh 参数在远端解码执行。grep -v 在“没有任何行被选中”时退出码为 1——当 authorized_keys 里只剩待删除的这一行时，过滤结果为空文件，这属于正常情况而非错误；真错误（如文件不可读）退出码为 2。因此必须检查退出码区分 0/1（正常，继续写回）与 2（异常，中止），不能用 && 串联 mv，否则“删除最后一行”时 mv 被短路跳过、公钥实际未被删除且脚本以退出码 1 结束。
cd || exit 1
umask 077
while IFS= read -r key || [ -n "$key" ]; do
    [ -n "$key" ] || continue
    if [ -f .ssh/authorized_keys ]; then
        grep -v -xF "$key" .ssh/authorized_keys > .ssh/authorized_keys.tmp
        rc=$?
        [ $rc -eq 0 ] || [ $rc -eq 1 ] || exit $rc
        mv .ssh/authorized_keys.tmp .ssh/authorized_keys
    fi
done <<'__SSH_COPY_ID_KEYS__'
__KEYS__
__SSH_COPY_ID_KEYS__
