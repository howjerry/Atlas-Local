# 安全：使用命名路由進行重導向
class SessionsController
  def after_login
    redirect_to root_path
  end

  def goto_dashboard
    redirect_to dashboard_path
  end
end
