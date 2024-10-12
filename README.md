### Important Note on Fastify Version Compatibility

As of today(2024-10-03), the `@nestjs/platform-fastify` package depends on **Fastify v4.28.1**, while the latest Fastify version is **5.0.0**. If you plan to use cookies in your application, you'll need the `@fastify/cookie` package. The current version of `@fastify/cookie` is **10.0.1** and it depends on Fastify's latest version.

This can lead to a TypeScript error when registering `fastifyCookie` from `@fastify/cookie` due to the version mismatch between Fastify and `@fastify/cookie`.

To resolve this issue:
- Downgrade Fastify to **v4.28.1** (as required by `@nestjs/platform-fastify`).
- Additionally, downgrade `@fastify/cookie` to **v9.4.0** to ensure compatibility with Fastify v4.

```bash
npm install fastify@4.28.1 @fastify/cookie@9.4.0
```