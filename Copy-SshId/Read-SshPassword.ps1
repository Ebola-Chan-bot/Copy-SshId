# askpass 辅助脚本：被 OpenSSH 的 SSH_ASKPASS 调用，从环境变量读密码并打印到 stdout。
# 密码由父进程通过环境变量「密码」传入（不落盘、无后台进程）。
# 注意：OpenSSH 调用 askpass 时会把提示语作为第一个参数传入，这里忽略之。
[Console]::Out.WriteLine($env:密码)
