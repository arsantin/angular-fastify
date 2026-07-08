// Require the framework and instantiate it

// ESM
import Fastify from "fastify";
import argon2 from "argon2";

const fastify = Fastify({
  logger: true
});
console.log(
  "process.env.BASE_URL_FRONT_DEVELOPMENT",
  process.env.BASE_URL_FRONT_DEVELOPMENT
);
fastify.register(import("@fastify/cors"), {
  // Allow the Angular dev server at localhost:4200
  origin: [process.env.BASE_URL_FRONT_DEVELOPMENT, process.env.BASE_URL_FRONT],
  methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  // If your front-end sends cookies or uses credentials, set this to true
  credentials: true
});
fastify.register(import("@fastify/jwt"), {
  secret: "supersecret"
});
// Prefer DATABASE_URL from the environment; keep a local fallback for dev.
const DEFAULT_DB = process.env.DATABASE_URL;
const connectionString = process.env.DATABASE_URL || DEFAULT_DB;
fastify.register(import("@fastify/postgres"), {
  connectionString
});

fastify.get("/", async (req, reply) => {
  return { hello: "world" };
});

fastify.post("/user", async (req, reply) => {
  const client = await fastify.pg.connect();
  console.log("XXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  console.log(client);
  try {
    const { username, email, password } = req.body;
    console.log("Received user creation request for username:", username);
    if (!username || !email || !password) {
      return reply
        .code(400)
        .send({ error: "username, email, and password are required" });
    }

    const hash = await argon2.hash(password);

    const result = await client.query(
      "INSERT INTO users (username, email, hash) VALUES ($1, $2, $3) RETURNING id, username, email",
      [username, email, hash]
    );
    console.log("User created with ID:", result.rows[0].id);

    return reply.code(201).send(result.rows[0]);
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: "internal server error" });
  } finally {
    client.release();
  }
});

fastify.post("/signin", async (req, reply) => {
  const body = req.body || {};
  const email = body.email;
  const password = body.password;
  if (!email || !password) {
    return reply.code(400).send({ error: "email and password are required" });
  }

  const client = await fastify.pg.connect();
  try {
    // Look up the user by email
    const res = await client.query(
      "SELECT id, username, email, hash FROM users WHERE email = $1 LIMIT 1",
      [email]
    );
    if (res.rowCount === 0) {
      return reply.code(401).send({ error: "invalid credentials" });
    }

    const user = res.rows[0];
    // Verify the provided password against stored argon2 hash
    let verified = false;
    try {
      verified = await argon2.verify(user.hash, password);
    } catch (err) {
      fastify.log.error("argon2 verify error: %o", err);
      return reply.code(500).send({ error: "internal server error" });
    }

    if (!verified) {
      return reply.code(401).send({ error: "invalid credentials" });
    }

    // Sign a minimal JWT payload
    const token = fastify.jwt.sign({
      id: user.id,
      email: user.email,
      roles: ["user:readonly"]
    });
    fastify.log.info("Generated JWT for user %s", user.email);
    return reply.send({ data: { token, email: user.email } });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: "internal server error" });
  } finally {
    client.release();
  }
});

fastify.post("/auth/validate", async (req, reply) => {
  console.log("hhhhhhhhhhhhhhhhhhhhhheaders", req.headers);
  try {
    const auth = req.headers.authorization || "";
    const parts = auth.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return reply
        .code(401)
        .send({ error: "missing or invalid authorization header" });
    }
    const token = parts[1];
    let payload;
    try {
      payload = fastify.jwt.verify(token);
    } catch (err) {
      fastify.log.info("JWT verify failed: %o", err);
      return reply.code(401).send({ error: "invalid token" });
    }
    return reply.send({ valid: true, payload });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: "internal server error" });
  }
});

// Run the server!
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

const start = async () => {
  try {
    const address = await fastify.listen({ port: PORT });
    fastify.log.info(`Server listening at ${address}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
