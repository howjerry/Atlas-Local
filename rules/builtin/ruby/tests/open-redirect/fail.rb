# 不安全：直接使用使用者輸入進行重導向
class SessionsController
  def after_login
    redirect_to(params[:return_url])
  end

  def goto
    redirect_to params[:url]
  end
end
