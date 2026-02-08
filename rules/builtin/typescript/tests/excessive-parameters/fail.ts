function createUser(
    name: string,
    email: string,
    age: number,
    role: string,
    department: string,
    isActive: boolean
) {
    return { name, email, age, role, department, isActive };
}

function sendNotification(userId: string, type: string, title: string, body: string, priority: number, channel: string) {
    return { userId, type, title, body, priority, channel };
}
