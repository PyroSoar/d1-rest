import { Hono, Context, Next } from "hono";
import { cors } from "hono/cors";
import { handleRest } from './rest';

export interface Env {
    DB: D1Database;
    SECRET: SecretsStoreSecret;
}

// # List all users
// GET /rest/users

// # Get filtered and sorted users
// GET /rest/users?age=25&sort_by=name&order=desc

// # Get paginated results
// GET /rest/users?limit=10&offset=20

// # Create a new user
// POST /rest/users
// { "name": "John", "age": 30 }

// # Update a user
// PATCH /rest/users/123
// { "age": 31 }

// # Delete a user
// DELETE /rest/users/123

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        const app = new Hono<{ Bindings: Env }>();

        // Apply CORS to all routes
        app.use('*', async (c, next) => {
            return cors()(c, next);
        })

        // Secret Store key value that we have set
        const secret = await env.SECRET.get();

        // Helper function to generate HMAC-SHA256 signature using Web Crypto API
        const generateSignature = async (secretKey: string, message: string): Promise<string> => {
            const encoder = new TextEncoder();
            const key = await crypto.subtle.importKey(
                'raw',
                encoder.encode(secretKey),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
            const hashArray = Array.from(new Uint8Array(signature));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        };

        // Authentication middleware that verifies encrypted Bearer token
        // Token format: salt:timestamp:signature
        // signature = HMAC_SHA256(secret, secret:timestamp:salt)
        // Timestamp must be within 1 minute of current time
        const authMiddleware = async (c: Context, next: Next) => {
            const authHeader = c.req.header('Authorization');
            if (!authHeader) {
                return c.json({ error: 'Unauthorized' }, 401);
            }

            const token = authHeader.startsWith('Bearer ')
                ? authHeader.substring(7)
                : authHeader;

            // Parse token format: salt:timestamp:signature
            const parts = token.split(':');
            if (parts.length !== 3) {
                return c.json({ error: 'Unauthorized' }, 401);
            }

            const [salt, timestampStr, providedSignature] = parts;

            // Verify timestamp is within 1 minute
            const timestamp = parseInt(timestampStr, 10);
            if (isNaN(timestamp)) {
                return c.json({ error: 'Unauthorized' }, 401);
            }

            const currentTime = Date.now();
            const timeDiff = Math.abs(currentTime - timestamp);
            const ONE_MINUTE = 60000;

            if (timeDiff > ONE_MINUTE) {
                return c.json({ error: 'Unauthorized' }, 401);
            }

            // Verify signature using HMAC-SHA256
            const message = `${secret}:${timestamp}:${salt}`;
            const expectedSignature = await generateSignature(secret, message);

            if (providedSignature !== expectedSignature) {
                return c.json({ error: 'Unauthorized' }, 401);
            }

            return next();
        };

        // CRUD REST endpoints made available to all of our tables
        // Health check root
        app.get('/', async (c) => {
            return c.text('Database Working.', 200);
        });

        app.all('/rest/*', authMiddleware, handleRest);

        // Execute a raw SQL statement with parameters with this route
        app.post('/query', authMiddleware, async (c) => {
            try {
                const body = await c.req.json();
                const { query, params } = body;

                if (!query) {
                    return c.json({ error: 'Query is required' }, 400);
                }
                
                // --- 防脱库逻辑开始 ---
                // 如果是 SELECT *，必须带 WHERE 或 LIMIT
                const normalized = query.trim().toUpperCase();
                if (normalized.startsWith("SELECT *")) {
                    const hasWhere = /WHERE/i.test(normalized);
                    const hasLimit = /LIMIT/i.test(normalized);
        
                    if (!hasWhere && !hasLimit) {
                        return c.json({
                            error: "SELECT * without WHERE or LIMIT is not allowed."
                        }, 400);
                    }
                }
                // --- 防脱库逻辑结束 ---
                
                // Execute the query against D1 database
                const results = await env.DB.prepare(query)
                    .bind(...(params || []))
                    .all();

                return c.json(results);
            } catch (error: any) {
                return c.json({ error: error.message }, 500);
            }
        });

        return app.fetch(request, env, ctx);
    }
} satisfies ExportedHandler<Env>;
