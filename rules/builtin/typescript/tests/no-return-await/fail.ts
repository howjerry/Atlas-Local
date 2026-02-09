// No Return Await: SHOULD trigger the rule
// Pattern: return statement with await expression

// 不必要的 return await
async function fetchUser(id: string) {
  return await getUserById(id);
}

// 在箭頭函式中
const getData = async () => {
  return await fetch("https://api.example.com/data");
};

// 在方法中
class UserService {
  async findAll() {
    return await this.repository.find();
  }
}
