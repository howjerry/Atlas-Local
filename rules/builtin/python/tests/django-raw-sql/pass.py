# Django Raw SQL: should NOT trigger the rule
# 使用 Django ORM 或硬編碼 SQL

from django.db import models

class User(models.Model):
    name = models.CharField(max_length=100)

def safe_orm_query(name):
    # 安全：使用 Django ORM
    users = User.objects.filter(name=name)
    return list(users)

def safe_raw_with_literal():
    # 安全：使用硬編碼的 SQL（字串字面量，非變數）
    users = User.objects.raw("SELECT * FROM auth_user WHERE is_active = TRUE")
    return list(users)

