<?php
// 不安全：使用 exec 執行外部指令
$dir = $_GET['dir'];
exec("ls -la " . $dir);

// 不安全：使用 system 執行外部指令
system($userCommand);

// 不安全：使用 shell_exec
shell_exec("ping " . $host);

// 不安全：使用 passthru
passthru("cat " . $filename);

// 不安全：使用 popen
popen("grep " . $pattern, "r");
