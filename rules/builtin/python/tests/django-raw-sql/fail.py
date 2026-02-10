# Django Raw SQL: SHOULD trigger the rule
# Pattern: Django 使用 raw SQL 查詢
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

from django.db import models
from django.db.models.expressions import RawSQL

class User(models.Model):
    name = models.CharField(max_length=100)

def unsafe_raw_query(query_str):
    # 不安全：raw 使用變數
    users = User.objects.raw(query_str)
    return list(users)

def unsafe_extra(where_clause):
    # 不安全：extra 使用變數
    users = User.objects.extra(where_clause)
    return list(users)

def unsafe_raw_sql(sql_expr):
    # 不安全：RawSQL 使用變數
    annotation = RawSQL(sql_expr)

