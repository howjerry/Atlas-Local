# Unsafe Reflection: should NOT trigger the rule
# 使用白名單驗證或硬編碼方法名稱

# 安全：使用硬編碼 symbol
user.send(:activate)

# 安全：使用白名單驗證
allowed_actions = %w[create update delete]
if allowed_actions.include?(params[:action])
  user.public_send(params[:action].to_sym)
end

