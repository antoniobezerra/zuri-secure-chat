FROM node:22-alpine
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/retention-worker ./apps/retention-worker
RUN pnpm install --frozen-lockfile=false
RUN pnpm --filter @zuri-secure-chat/retention-worker build
CMD ["pnpm", "--filter", "@zuri-secure-chat/retention-worker", "start"]

