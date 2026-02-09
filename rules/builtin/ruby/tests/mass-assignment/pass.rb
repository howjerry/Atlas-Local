# 安全：使用 permit 搭配明確的允許清單
class UsersController
  def create
    user = User.new(user_params)
    user.save
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :age)
  end
end
