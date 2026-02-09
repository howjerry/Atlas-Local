# 不安全：使用字串內插傳遞指令（SAST 測試夾具）
class DeployService
  def run_deploy(branch)
    system("git checkout #{branch}")
  end
end
