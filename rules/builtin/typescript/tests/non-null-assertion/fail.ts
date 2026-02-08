const len = value!.length;

function getUser(map: Map<string, User>) {
    const user = map.get("admin")!;
    return user.name;
}

const first = items!.pop()!;
