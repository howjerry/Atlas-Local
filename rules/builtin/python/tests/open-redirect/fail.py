# 開放重導向漏洞：應觸發規則
# 將使用者輸入直接傳遞給重導向函式

from django.shortcuts import redirect
from django.http import HttpResponseRedirect

def unsafe_redirect_view(request):
    # 直接使用 request 參數進行重導向（不安全）
    next_url = request.GET.get("next")
    return redirect(request.POST.get("url"))

def unsafe_http_redirect(request):
    return HttpResponseRedirect(request.GET.get("redirect_to"))
