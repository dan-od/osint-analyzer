FROM node:22-alpine

WORKDIR /app

# Toolchain in case better-sqlite3 has to compile its native module
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# SQLite database, blocklist feed cache and optional IP2Proxy BIN file
VOLUME /app/data

EXPOSE 3000

CMD ["npm", "start"]
