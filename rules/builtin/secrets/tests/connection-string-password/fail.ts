// Connection String Password: SHOULD trigger the rule
// Pattern: string matching ://user:password@host
// NOTE: This is a SAST test fixture with FAKE connection strings

const dbUrl = "postgresql://admin:s3cretP4ss@db.example.com:5432/mydb";

const mongoUri = "mongodb://root:hunter2pass@mongo.example.com:27017/app";

const redisUrl = "redis://default:myredispass@redis.example.com:6379";

const amqpUrl = "amqp://guest:guestpass@rabbit.example.com:5672/vhost";
