const len = value?.length ?? 0;

function getUser(map: Map<string, User>) {
    const user = map.get("admin");
    if (user) {
        return user.name;
    }
    return null;
}

const first = items?.pop() ?? defaultItem;
