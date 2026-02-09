# 安全：使用陣列傳遞指令參數，避免 shell 解析
require "open3"

class DeployService
  def run_deploy(branch)
    system("git", "checkout", branch)
  end

  def safe_capture(command, arg)
    Open3.capture3(command, arg)
  end
end
