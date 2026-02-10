# CSRF Disabled: SHOULD trigger the rule
# Pattern: Rails controller 停用 CSRF 保護
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

class UnsafeController < ApplicationController
  # 不安全：跳過 CSRF 驗證
  skip_before_action :verify_authenticity_token

  # 不安全：使用 null_session
  protect_from_forgery with: :null_session

  def create
    User.create(params[:user])
  end
end

