# 远程引导脚本：由 通过scp执行远程Windows脚本 上传目标脚本后，经 ssh 用 -EncodedCommand 引导执行。
# 流程：执行已上传到远端用户目录的临时脚本 → 记录退出码 → 删除远端临时文件 → 原样返回退出码。整体 -EncodedCommand 编码后只有纯 base64，远端任何 shell 都不会拆解；第 3 行的随机临时文件名占位符由调用方替换（本注释中不写出该占位符字面量，避免被一并替换）。-ExecutionPolicy Bypass 保证文件执行不受远端执行策略限制（由调用方在命令行传入，不在本脚本内）。
$ProgressPreference = 'SilentlyContinue'
$p = Join-Path $env:USERPROFILE '__REMOTE_SCRIPT_NAME__'
& $p
$ec = $LASTEXITCODE
Remove-Item $p -Force -ErrorAction SilentlyContinue
exit $ec
