# 不安全：使用 html_safe 或 raw 輸出未過濾的使用者輸入
class PostHelper
  def render_content(user_input)
    user_input.html_safe
  end

  def render_raw(content)
    raw(content)
  end
end
