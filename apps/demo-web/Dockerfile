FROM node:22-alpine
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml tsconfig.base.json ./
COPY packages ./packages
COPY apps/demo-web ./apps/demo-web
RUN pnpm install --frozen-lockfile=false
EXPOSE 5177
CMD ["pnpm", "--filter", "@zuri-secure-chat/demo-web", "dev"]

