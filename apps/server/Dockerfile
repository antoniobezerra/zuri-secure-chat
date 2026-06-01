FROM node:22-alpine
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml tsconfig.base.json ./
COPY packages ./packages
COPY apps/server ./apps/server
RUN pnpm install --frozen-lockfile=false
RUN pnpm --filter @zuri-secure-chat/server build
EXPOSE 4088
CMD ["pnpm", "--filter", "@zuri-secure-chat/server", "start"]

