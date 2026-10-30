# paranoid-gateway

The part of [PARANOID](https://paranoid.red) that sees questions, tickets and keys. It runs on its own in an
Intel TDX confidential VM on Phala Cloud (dstack), and the PARANOID app checks the chip's proof before it
sends anything to it.

The code here is the gateway exactly as it runs: `gate/` is a small Node server, and `web/` holds the
PARANOID site files it serves (the route handlers under `web/app` and the libraries under `web/lib`),
copied unchanged from the site. The protocol itself (program, circuit, ceremony) lives in
[paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid).

## What it serves

| Path | What |
| --- | --- |
| `/api/v1/chat/completions`, `/api/v1/models`, `/api/v1/used` | The OpenAI-compatible API: a ZK proof of a paid ticket instead of an account |
| `/api/v1/e2e/*` | Questions sealed in the browser to a model's own chip |
| `/api/ohttp`, `/api/ohttp/config` | Sealed requests (Oblivious HTTP, RFC 9458), with or without a relay |
| `/api/search` | Web search for a paid ticket |
| `/mcp/<url>`, `/api/mcp/url` | The remote MCP server |
| `/api/x402/join`, `/api/zec`, `/api/zec/status` | Buying questions with x402 or Zcash |
| `/api/rpc`, `/zk/*` | Public chain reads and circuit files, so a connector needs one address |
| `/api/gate/attest?nonce=<64 hex>` | The chip's proof |

## The proof

On the chip, the key that opens sealed requests is derived inside it with dstack `GetKey`
(path `paranoid/ohttp/v1`). A seed passed in through the environment is ignored, so nobody holding the
deployment settings can open a sealed request. Requests opened inside are answered inside: the server's
own address is fixed to `127.0.0.1`.

`/api/gate/attest` returns a TDX quote whose report_data is the SHA-256 of

    {"key_config":"<OHTTP key config, base64>","nonce":"<your nonce>","purpose":"paranoid.gateway.v1"}

followed by zeros, together with the boot event log, the app compose file and Intel's collateral for the
quote. The PARANOID app checks, in this order:

1. Intel's signature on the quote, against Intel's collateral, with status `UpToDate`
2. report_data names this key config and the app's fresh nonce, and the TD is not in debug mode
3. the boot log replays to RTMR3, its `compose-hash` event is the SHA-256 of the compose file, and the
   compose hash and boot measurements (MRTD, RTMR0 to RTMR2) are those of a published build

Only then does it seal a request to that key.

## Reproduce the image

    ./build.sh

builds `linux/amd64` with every timestamp clamped to `SOURCE_DATE_EPOCH`, so a given commit gives the same
image id anywhere. Each release lists the image id and the digest pushed to
`ghcr.io/paranoiddotred/paranoid-gateway`. To check a release:

    docker pull ghcr.io/paranoiddotred/paranoid-gateway@sha256:<digest from the release>
    docker image inspect --format '{{.Id}}' ghcr.io/paranoiddotred/paranoid-gateway@sha256:<digest>

and compare it with the id `./build.sh` printed for the release's commit. `docker-compose.yml` is the file
the box runs; its SHA-256 is the compose hash in the boot log.

## Test

    npm ci
    node test/dstack-stub.ts serve 41702 &
    ./build.sh paranoid-gateway:test
    SEED=$(openssl rand -hex 32)
    docker run -d --network host -e PORT=47300 -e DSTACK_SIMULATOR_ENDPOINT=http://127.0.0.1:41702 \
      -e PARANOID_OHTTP_SEED=$SEED paranoid-gateway:test
    GATE=http://127.0.0.1:47300 ENV_SEED=$SEED node test/gate-attest.ts

`test/dstack-stub.ts` stands in for the dstack socket with a quote laid out like the real one but not signed
by Intel. `test/gate-attest.ts` checks that the key comes from the chip and not the settings, that the quote
binds the key and the nonce, that the boot log matches the compose file, and that a request sealed to the
proven key is answered. Node.js 22.18 or later runs the TypeScript directly.

## License

MIT
