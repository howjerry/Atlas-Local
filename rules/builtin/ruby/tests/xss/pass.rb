# 安全：使用 sanitize 過濾 HTML 內容
class PostHelper
  def render_content(user_input)
    sanitize(user_input)
  end

  def render_escaped(content)
    ERB::Util.html_escape(content)
  end
end
