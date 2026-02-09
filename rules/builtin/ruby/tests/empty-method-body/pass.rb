# 良好：方法有實際的實作內容
class Animal
  def speak
    raise NotImplementedError, "Subclass must implement #speak"
  end

  def move
    @position += 1
  end
end
