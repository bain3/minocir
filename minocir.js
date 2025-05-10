import * as crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

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
    `.split('\n').map(l => l.trim()).filter(l => l).join('\n') + '\n');
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

        throw new ApiError(401, JSON.stringify({
            errors: [{
                code: 'UNAUTHORIZED',
                message: 'authentication required',
                detail: 'authentication required',
            }]
        }), {
            headers: {
                'WWW-Authenticate': 'Basic realm="minocir" charset="UTF-8"',
                'Content-Type': 'application/json',
                'Docker-Distribution-API-Version': 'registry/2.0',
            }
        });
    }

    assert(req.headers.has('authorization'));

    let auth = req.headers.get('authorization');

    let m = auth.trim().match(/^basic[ ]+([a-z0-9+/]{1,500}={0,2})$/i);
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

// {{{ File server

function file_server(root) {
    return {
        head: async (filename) => {
            const file_path = path.join(root, filename);
            const f = Bun.file(file_path);

            if (!await f.exists()) {
                throw new ApiError(404, null);
            }

            const hash = await streamHash(Bun.file(file_path).stream(), 'sha256');

            return new Response(null, {
                headers: {
                    'Docker-Content-Digest': `sha256:${hash}`,
                },
            });
        },

        get: async (filename) => {
            const file_path = path.join(root, filename);
            const f = Bun.file(file_path);

            if (!await f.exists()) {
                throw new ApiError(404, null);
            }

            const hash = await streamHash(Bun.file(file_path).stream(), 'sha256');

            return new Response(f, {
                headers: {
                    'Docker-Content-Digest': `sha256:${hash}`,
                },
            });
        },
    }
}

// }}}

const upload_sessions = {};
// XXX: clean up old sessions

const routes = {};

routes["/v2/"] = {
    GET: async req => {
        console.log(req);
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
}

routes["/v2/sessions/:filename"] = {
    PATCH: async req => {
        const entry = upload_sessions[req.params.filename];
        if (!entry || entry.lock) throw new ApiError(404, "session not found");

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

function manifest_filename(repo, image, ref) {
    return `${repo}:${image}:${ref}`;
}

async function resolve_manifest_reference(repo, image, ref) {
    const real_path = await fs.realpath(path.join(MANIFEST_ROOT, manifest_filename(repo, image, ref)));
    return path.basename(real_path);
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

        if (await fs.readlink(reference_full_path)) {
            await fs.unlink(reference_full_path);
        }

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
        const f = Bun.file(path.join(MANIFEST_ROOT, reference_filename));

        if (!await f.exists()) {
            throw new ApiError(404, "manifest not found");
        }

        const hash = await streamHash(f.stream());

        return new Response(null, {
            headers: {
                'Docker-Content-Digest': `sha256:${hash}`,
                'Content-Type': MANIFEST_MIME_TYPE,
            }
        });
    },

    GET: async req => {
        await authenticate(req, 'r');

        const reference_filename = manifest_filename(req.params.repo, req.params.image, req.params.reference);
        const f = Bun.file(path.join(MANIFEST_ROOT, reference_filename));

        if (!await f.exists()) {
            throw new ApiError(404, "manifest not found");
        }

        const hash = await streamHash(f.stream());

        return new Response(f, {
            headers: {
                'Docker-Content-Digest': `sha256:${hash}`,
                'Content-Type': MANIFEST_MIME_TYPE,
            }
        });
    },

    DELETE: async req => {
        await authenticate(req, 'w');

        const manifest_filename = await resolve_manifest_reference(req.params.repo, req.params.image, req.params.reference);

        await fs.unlink(path.join(MANIFEST_ROOT, manifest_filename));
        // XXX: clean up symlinked files

        return new Response();
    }
};

const blob_fs = file_server(BLOB_ROOT);

routes["/v2/:repo/:image/blobs/:digest"] = {
    HEAD: async req => {
        await authenticate(req, 'r');
        return await blob_fs.head(req.params.digest)
    },
    GET: async req => {
        await authenticate(req, 'r');
        return await blob_fs.get(req.params.digest)
    },
};

console.log(`Starting minocir at http://${env.BIND_ADDR}:${env.BIND_PORT}`);

for (let file of await fs.readdir(SESSION_ROOT)) {
    await fs.unlink(path.join(SESSION_ROOT, file));
}

Bun.serve({
    port: env.BIND_PORT,
    hostname: env.BIND_ADDR,
    routes,

    async error(err) {
        if (err instanceof ApiError) {
            return new Response(err.message, {
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
        console.log(req);
        return new Response(null, {
            status: 404,
        })
    },
});
