# Miniature OCI Registry

Minocir is an exremely minimal OCI/Docker registry. It is a single `js` file written for `bun`.

Features:

- pull
- push
- authentication

This is not meant to be a full fledged registry. It is the bare minimum to have a working
registry, so that you can share images without sending tarballs.

Everything is kept inside a single directory. User management is done through a passwd-like
file. User _tokens_ are stored in plain text. I am intentionally calling them tokens, because
you should not store user generated passwords there.

## Usage

0. (optionally) compile to a binary using bun: `bun build --compile --target=bun-linux-x64 minocir.js --outfile minocir`
1. Run the `js` file or binary with the following environment variables:
   ```
   BIND_ADDR=0.0.0.0 # address to bind to
   BIND_PORT=8000 # port to bind to
   DATA_REPO=./data # storage directory (must exist)
   ```
3. Modify `$DATA_REPO/access` to define users and tokens.
4. Set up a reverse proxy in front of it. It does not support HTTPS right now.
