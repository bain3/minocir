import * as crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { setTimeout } from 'node:timers';

const env = {
    BIND_PORT: Number(process.env.BIND_PORT || 8080),
    BIND_ADDR: process.env.BIND_ADDR || '0.0.0.0',
    DATA_REPO: path.resolve(process.env.DATA_REPO || './data'),
};

// Minocir only supports manifest v2 for now.
const MANIFEST_MIME_TYPE = "application/vnd.docker.distribution.manifest.v2+json";

const BLOB_ROOT = path.join(env.DATA_REPO, 'blobs');
const SESSION_ROOT = path.join(env.DATA_REPO, 'sessions');
const MANIFEST_ROOT = path.join(env.DATA_REPO, 'manifests');

async function get_users() {
    let access_file = Bun.file(path.join(env.DATA_REPO, 'access'));
    const access = {};

    await fs.mkdir(BLOB_ROOT, { recursive: true })
    await fs.mkdir(SESSION_ROOT, { recursive: true })
    await fs.mkdir(MANIFEST_ROOT, { recursive: true })

    if (await access_file.exists()) {
        for (let line of (await access_file.text()).split('\n')) {
            line = line.trim();
            if (line.startsWith('#') || !line) continue;

            const parts = line.split(":");
            if (parts.length != 3) {
                console.log('skipping invalid line');
                continue;
            }

            let [user, token, perms] = parts;

            access[user] = { token, perms };
        }
    } else {
        await Bun.write(access_file, `
            # User definition file
            # format: user:token:perms
            # perms is a string made of 'r' for read, 'w' for write
            # Beware, token is in plain text. Only use generated tokens, not user passwords.
            # The special combination *:* is anonymous access
            *:*:r
        `.split('\n').map(l => l.trim()).filter(l => l).join('\n') + '\n');
    }

    return access;
}

async function count_blob_references() {
    const blob_rc = {};

    for (let blob of await fs.readdir(BLOB_ROOT)) {
        blob_rc[blob] = 0;
    }

    for (let file of await fs.readdir(MANIFEST_ROOT)) {
        const filepath = path.join(MANIFEST_ROOT, file);

        // filter out symlinks
        try {
            await fs.readlink(filepath);
            continue;
        } catch (e) { }

        try {
            const manifest = await Bun.file(filepath).json();

            blob_rc[manifest.config.digest] += 1;
            for (let layer of manifest.layers) {
                blob_rc[layer.digest] += 1;
            }
        } catch (e) {
            console.warn("blob counting: could not process manifest", file);
            console.debug(e);
        }
    }

    return blob_rc;
}


class ApiError extends Error {
    constructor(status, message, params = null) {
        super(message);
        this.status = status;
        this.params = params;
    }
}

async function authenticate(req, perm) {
    if (!perm) {
        throw new Error('authenticate did not receive required perms');
    }

    function assert(predicate) {
        if (predicate) return;

        const hostname = req.headers.get('host');
        if (!hostname) {
            throw new ApiError(400, "Host header not present. Cannot create token.");
        }

        throw new ApiError(401, JSON.stringify({
            errors: [{
                code: 'UNAUTHORIZED',
                message: 'authentication required',
                detail: 'authentication required',
            }]
        }), {
            headers: {
                'WWW-Authenticate': `Bearer realm="https://${hostname}/v2/token",service="minocir"`,
                'Content-Type': 'application/json',
                'Docker-Distribution-API-Version': 'registry/2.0',
            }
        });
    }

    assert(req.headers.has('authorization'));

    let auth = req.headers.get('authorization');

    // allow sending basic auth as a bearer token, too
    let m = auth.trim().match(/^(?:basic|bearer)[ ]+([a-z0-9+/]{1,500}={0,2})$/i);
    assert(m);

    let [user, pass] = Buffer.from(m[1], 'base64').toString().split(':', 2);


    assert(access[user] != null);

    let a = Buffer.from(pass);
    let b = Buffer.from(access[user].token);

    assert(a.length == b.length && crypto.timingSafeEqual(a, b));

    assert(access[user].perms.includes(perm));
}

async function streamHash(stream, algorithm = 'sha256') {
    const shasum = crypto.createHash(algorithm);

    await stream.pipeTo(new WritableStream({
        write(chunk) {
            shasum.update(chunk);
        },
        close() { }
    }));

    return shasum.digest('hex');
}

// XXX: clean up old sessions
const upload_sessions = {};
const access = await get_users();

// for restricting garbage collection
let last_upload = 0;

const routes = {};

routes["/v2/token"] = {
    GET: async req => {
        // XXX: We're returning the basic auth. Not very secure...
        if (req.headers.has('authorization')) {
            return Response.json({ token: req.headers.get('authorization').replace(/^basic /i, "") });
        } else {
            return Response.json({ token: "Kjoq" }); // *:* base64 encoded
        }
    }
};

routes["/v2/"] = {
    GET: async req => {
        await authenticate(req, 'r');
        return new Response();
    }
};

routes["/v2/:repo/:image/blobs/uploads/"] = {
    POST: async req => {
        await authenticate(req, 'w');

        const filename = crypto.randomBytes(16).toString('hex');
        const file = Bun.file(path.join(SESSION_ROOT, filename)).writer();

        upload_sessions[filename] = {
            file,
            ts: Date.now(),
            written: 0,
            image: [req.params.repo, req.params.image],
            checksum: crypto.createHash('sha256'),
        };

        return new Response(null, {
            status: 202,
            headers: {
                'Location': `/v2/sessions/${filename}`
            },
        });
    },
};

routes["/v2/sessions/:filename"] = {
    PATCH: async req => {
        const entry = upload_sessions[req.params.filename];
        if (!entry || entry.lock) throw new ApiError(404, "session not found");

        last_upload = Date.now();

        try {
            entry.lock = true;

            await req.body.pipeTo(new WritableStream({
                write(chunk) {
                    entry.file.write(chunk);
                    entry.checksum.update(chunk);
                    entry.written += chunk.length;
                },
                close() { }
            }));

            return new Response(null, {
                status: 202,
                headers: {
                    'Range': `0-${entry.written}`,
                },
            });
        } finally {
            entry.lock = false;
        }

    },

    PUT: async req => {
        const entry = upload_sessions[req.params.filename];
        if (!entry || entry.lock) throw new ApiError(404, "session not found");
        try {
            entry.lock = true;

            const digest = new URL(req.url).searchParams.get('digest');
            const hash = entry.checksum.digest('hex');

            if (!digest.startsWith('sha256:')) {
                console.warn('Could not verify digest. We only support SHA256.');
            } else if (digest != `sha256:${hash}`) {
                throw new ApiError(400, 'Digest does not match.');
            }


            const { file, written, image } = entry;

            console.log('Finish uploading', image, digest);

            file.end();

            await fs.rename(
                path.join(SESSION_ROOT, req.params.filename),
                path.join(BLOB_ROOT, digest),
            );

            delete upload_sessions[req.params.filename];

            const blob_url = `/v2/${image[0]}/${image[1]}/blobs/${digest}`;
            return new Response(null, {
                status: 202,
                headers: {
                    'Range': `0-${written}`,
                    'Location': blob_url,
                },
            });
        } finally {
            entry.lock = false;
        }
    },

    DELETE: async req => {
        const entry = upload_sessions[req.params.filename];
        if (!entry || entry.lock) throw new ApiError(404, "session not found");

        const { file } = entry;

        console.log("Upload cancelled");

        file.end();

        await fs.unlink(path.join(SESSION_ROOT, req.params.filename));

        return new Response();
    }
};

async function get_file_with_digest(root, filename, with_body) {
    const file_path = path.join(root, filename);
    const f = Bun.file(file_path);

    if (!await f.exists()) {
        throw new ApiError(404, null);
    }

    const hash = await streamHash(f.stream(), 'sha256');

    return new Response(with_body ? f : null, {
        headers: {
            'Docker-Content-Digest': `sha256:${hash}`,
        },
    });
}

function manifest_filename(repo, image, ref) {
    return `${repo}:${image}:${ref}`;
}

routes["/v2/:repo/:image/manifests/:reference"] = {
    PUT: async req => {
        await authenticate(req, 'w');

        // manifests are not large, we can have them in memory
        const manifest = await req.blob();

        const hash = await streamHash(manifest.stream(), 'sha256');
        const canon_filename = manifest_filename(req.params.repo, req.params.image, `sha256:${hash}`);

        await Bun.write(Bun.file(path.join(MANIFEST_ROOT, canon_filename)), manifest);

        // XXX: user can provide a reference "sha256:..." which falsely points to a different manifest
        // currently out of threat model
        const reference_filename = manifest_filename(req.params.repo, req.params.image, req.params.reference);
        const reference_full_path = path.join(MANIFEST_ROOT, reference_filename);

        try {
            await fs.readlink(reference_full_path);
            await fs.unlink(reference_full_path);
        } catch (e) { }

        await fs.symlink(canon_filename, reference_full_path);

        console.log("Uploaded image manifest", `${req.params.repo}/${req.params.image}:${req.params.reference}`);

        return new Response(null, {
            status: 201,
            headers: {
                'Location': `/v2/${req.params.repo}/${req.params.image}/manifests/${req.params.reference}`,
                'Docker-Content-Digest': `sha256:${hash}`,
            },
        });
    },

    HEAD: async req => {
        await authenticate(req, 'r');

        const reference_filename = manifest_filename(req.params.repo, req.params.image, req.params.reference);

        const response = await get_file_with_digest(MANIFEST_ROOT, reference_filename, false);
        response.headers.set('Content-Type', MANIFEST_MIME_TYPE);

        return response;
    },

    GET: async req => {
        await authenticate(req, 'r');

        const reference_filename = manifest_filename(req.params.repo, req.params.image, req.params.reference);

        const response = await get_file_with_digest(MANIFEST_ROOT, reference_filename, true);
        response.headers.set('Content-Type', MANIFEST_MIME_TYPE);

        return response;
    },

    DELETE: async req => {
        await authenticate(req, 'w');

        const reference_filename = manifest_filename(req.params.repo, req.params.image, req.params.reference);

        try {
            await fs.unlink(path.join(MANIFEST_ROOT, reference_filename));
        } catch (e) {
            // the manifest reference does not exist
            return new Response();
        }

        // clean up manifest symlinks
        for (let filename of await fs.readdir(MANIFEST_ROOT)) {
            try {
                const f = path.join(MANIFEST_ROOT, filename);
                if (await Bun.file(f).exists()) {
                    continue;
                }

                await fs.unlink(f);
            } catch (e) { }
        }

        return new Response();
    }
};

routes["/v2/:repo/:image/blobs/:digest"] = {
    HEAD: async req => {
        await authenticate(req, 'r');
        return await get_file_with_digest(BLOB_ROOT, req.params.digest, false);
    },
    GET: async req => {
        await authenticate(req, 'r');
        return await get_file_with_digest(BLOB_ROOT, req.params.digest, true);
    },
};

console.log(`Starting minocir at http://${env.BIND_ADDR}:${env.BIND_PORT}`);

for (let file of await fs.readdir(SESSION_ROOT)) {
    await fs.unlink(path.join(SESSION_ROOT, file));
}

const SESSION_EXPIRATION = 60 * 60 * 1000;
const MIN_INACITIVTY = 5 * 60 * 1000;
const GC_INTERVAL = 30 * 60 * 1000;

async function garbage_collection() {
    if (last_upload > Date.now() - MIN_INACITIVTY) {
        setTimeout(garbage_collection, GC_INTERVAL);
        return;
    }

    // clean up blobs
    const blob_refs = await count_blob_references();
    for (let blob of Object.keys(blob_refs)) {
        if (blob_refs[blob] <= 0) {
            try {
                await fs.unlink(path.join(BLOB_ROOT, blob));
            } catch (e) {
                console.warn("garbage_collection: cannot unlink", blob);
            }
        }
    }

    // clean up old sessions
    for (let session of Object.keys(upload_sessions)) {
        if (upload_sessions[session].ts <= Date.now() - SESSION_EXPIRATION) {
            upload_sessions[session].file.end();
            delete upload_sessions[session];
        }
    }

    setTimeout(garbage_collection, GC_INTERVAL);
}

garbage_collection();

Bun.serve({
    port: env.BIND_PORT,
    hostname: env.BIND_ADDR,
    routes,

    async error(err) {
        if (err instanceof ApiError) {
            return new Response(err.message || null, {
                status: err.status,
                ...err.params,
            });
        } else {
            console.error(err);
            return new Response("Internal server error", {
                status: 500,
            });
        }
    },

    async fetch(req) {
        return new Response(null, {
            status: 404,
        })
    },
});
