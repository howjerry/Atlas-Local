# 安全的重導向：不應觸發規則
# 使用硬編碼路徑或經驗證的 URL 進行重導向

from django.shortcuts import redirect

def safe_redirect_view(request):
    # 使用硬編碼的安全路徑
    return redirect("/dashboard/")

def safe_named_redirect(request):
    # 使用 Django 命名路由
    return redirect("home")
