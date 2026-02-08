interface CreateUserOptions {
    name: string;
    email: string;
    age: number;
    role: string;
    department: string;
    isActive: boolean;
}

function createUser(options: CreateUserOptions) {
    return { ...options };
}

function add(a: number, b: number, c: number) {
    return a + b + c;
}
