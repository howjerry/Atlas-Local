# CSRF Disabled: should NOT trigger the rule
# 使用正確的 CSRF 保護設定

class SafeController < ApplicationController
  # 安全：使用 exception 處理 CSRF
  protect_from_forgery with: :exception

  def create
    User.create(user_params)
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end
end

