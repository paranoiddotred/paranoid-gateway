# The PARANOID gateway image. Built from a folder that holds only the gateway's own files and the site
# files it runs (the root of the public paranoid-gateway repo), with timestamps clamped by build.sh, so
# the same commit gives the same image for anyone who builds it.
FROM node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da

ENV NODE_ENV=production \
    PORT=8080 \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && rm -rf /root/.npm /tmp/*

COPY web ./web
COPY gate ./gate

# The data folder belongs to the user the server runs as, so a fresh volume mounted there (spent tickets,
# x402 and Zcash books) starts writable.
RUN mkdir /data && chown node:node /data

USER node
EXPOSE 8080
CMD ["node", "gate/main.mjs"]
