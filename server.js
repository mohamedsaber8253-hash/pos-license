'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');

const host = process.env.LICENSE_HOST || '127.0.0.1';
const port = Number(process.env.LICENSE_PORT || 8090);
const adminToken = process.env.LICENSE_ADMIN_TOKEN || '';
const dataFile = path.resolve(process.env.LICENSE_DB_PATH || path.join(__dirname, 'data', 'licenses.json'));
const maximumBodyBytes = 16 * 1024;
let writes = Promise.resolve();

if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('LICENSE_PORT must be a valid TCP port.');
}
if (Buffer.byteLength(adminToken, 'utf8') < 32) {
    throw new Error('Set LICENSE_ADMIN_TOKEN to a random secret of at least 32 bytes.');
}

function sendJson(response, status, value) {
    response.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    });
    response.end(JSON.stringify(value));
}

function isAuthorized(request) {
    const authorization = request.headers.authorization || '';
    const supplied = Buffer.from(authorization.replace(/^Bearer\s+/i, ''), 'utf8');
    const expected = Buffer.from(adminToken, 'utf8');
    return /^Bearer\s+/i.test(authorization) &&
        supplied.length === expected.length &&
        crypto.timingSafeEqual(supplied, expected);
}

async function readDatabase() {
    try {
        const content = await fs.readFile(dataFile, 'utf8');
        const parsed = JSON.parse(content);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('License data must be a JSON object.');
        }
        return parsed;
    } catch (error) {
        if (error.code === 'ENOENT') return {};
        throw error;
    }
}

function updateDatabase(record) {
    writes = writes.catch(() => {}).then(async () => {
        const database = await readDatabase();
        database[record.machineId] = record;
        await fs.mkdir(path.dirname(dataFile), { recursive: true });
        const temporaryFile = `${dataFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
        await fs.writeFile(temporaryFile, `${JSON.stringify(database, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
        await fs.rename(temporaryFile, dataFile);
    });
    return writes;
}

async function readRequestBody(request) {
    let body = '';
    for await (const chunk of request) {
        body += chunk;
        if (Buffer.byteLength(body, 'utf8') > maximumBodyBytes) {
            const error = new Error('Request body is too large.');
            error.statusCode = 413;
            throw error;
        }
    }
    try {
        return JSON.parse(body);
    } catch {
        const error = new Error('Request body must be valid JSON.');
        error.statusCode = 400;
        throw error;
    }
}

function normalizeLicense(input) {
    const machineId = String(input.machineId || '').toUpperCase();
    const restaurant = String(input.restaurant || '');
    if (!/^[A-F0-9]{64}$/.test(machineId)) {
        throw Object.assign(new Error('machineId must be a 64-character device ID.'), { statusCode: 400 });
    }
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(restaurant)) {
        throw Object.assign(new Error('restaurant must contain 1-64 letters, numbers, underscores, or hyphens.'), { statusCode: 400 });
    }
    if (typeof input.enabled !== 'boolean') {
        throw Object.assign(new Error('enabled must be true or false.'), { statusCode: 400 });
    }

    let expiresAt = null;
    if (input.expiresAt !== null) {
        if (typeof input.expiresAt !== 'string' ||
            !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(input.expiresAt) ||
            !Number.isFinite(Date.parse(input.expiresAt))) {
            throw Object.assign(new Error('expiresAt must be a UTC timestamp ending in Z, or null for lifetime.'), { statusCode: 400 });
        }
        expiresAt = new Date(input.expiresAt).toISOString();
    }

    return {
        machineId,
        restaurant,
        enabled: input.enabled,
        expiresAt,
        updatedAt: new Date().toISOString()
    };
}

function publicStatus(record, now = new Date()) {
    if (!record) {
        return {
            found: false,
            active: false,
            reason: 'not_found',
            expiresAt: null,
            serverTime: now.toISOString()
        };
    }

    const expired = record.expiresAt !== null && Date.parse(record.expiresAt) <= now.getTime();
    const active = record.enabled === true && !expired;
    return {
        found: true,
        active,
        reason: active ? '' : (expired ? 'expired' : 'revoked'),
        expiresAt: record.expiresAt,
        restaurant: record.restaurant,
        serverTime: now.toISOString()
    };
}

const server = http.createServer(async (request, response) => {
    try {
        const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
        if (request.method === 'GET' && url.pathname === '/health') {
            sendJson(response, 200, { ok: true, service: 'RestaurantPOS licensing' });
            return;
        }

        if (request.method === 'GET' && url.pathname === '/v1/admin/licenses') {
            if (!isAuthorized(request)) {
                sendJson(response, 401, { error: 'Unauthorized.' });
                return;
            }
            const database = await readDatabase();
            const now = new Date();
            const licenses = Object.values(database)
                .sort((left, right) => left.restaurant.localeCompare(right.restaurant))
                .map(record => ({ ...record, ...publicStatus(record, now) }));
            sendJson(response, 200, { licenses, serverTime: now.toISOString() });
            return;
        }

        if (request.method === 'POST' && url.pathname === '/v1/admin/licenses') {
            if (!isAuthorized(request)) {
                sendJson(response, 401, { error: 'Unauthorized.' });
                return;
            }
            const record = normalizeLicense(await readRequestBody(request));
            await updateDatabase(record);
            sendJson(response, 200, publicStatus(record));
            return;
        }

        const clientMatch = url.pathname.match(/^\/v1\/licenses\/([A-Fa-f0-9]{64})$/);
        if (request.method === 'GET' && clientMatch) {
            const database = await readDatabase();
            sendJson(response, 200, publicStatus(database[clientMatch[1].toUpperCase()]));
            return;
        }

        sendJson(response, 404, { error: 'Not found.' });
    } catch (error) {
        sendJson(response, error.statusCode || 500, {
            error: error.statusCode ? error.message : 'Internal licensing service error.'
        });
        if (!error.statusCode) console.error('[license-server]', error);
    }
});

server.listen(port, host, () => {
    console.log(`RestaurantPOS licensing service listening on http://${host}:${port}`);
    console.log(`License data file: ${dataFile}`);
});

server.on('error', error => {
    console.error('[license-server] Failed to start:', error);
    process.exitCode = 1;
});
