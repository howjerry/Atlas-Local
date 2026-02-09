# TODO: 需要實作快取機制
class UserService
  # FIXME: 此方法在高負載下可能有效能問題
  def find_user(id)
    User.find(id)
  end

  # HACK: 暫時解法，之後需要重構
  def legacy_method
    42
  end
end
