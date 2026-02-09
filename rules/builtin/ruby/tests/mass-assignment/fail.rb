# 不安全：使用 permit! 允許所有參數
class UsersController
  def create
    user = User.new(params.permit!)
    user.save
  end

  def update
    @user.update(params[:user].permit!)
  end
end
