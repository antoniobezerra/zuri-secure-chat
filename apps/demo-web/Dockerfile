FROM node:22-alpine
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml tsconfig.base.json ./
COPY packages ./packages
COPY apps/demo-web ./apps/demo-web
RUN pnpm install --frozen-lockfile=false
RUN pnpm --filter @zuri-secure-chat/protocol build && pnpm --filter @zuri-secure-chat/web-sdk build
EXPOSE 5177
CMD ["pnpm", "--filter", "@zuri-secure-chat/demo-web", "dev"]
