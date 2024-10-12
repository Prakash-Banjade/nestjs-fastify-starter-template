### Version Compatibility Note
As of today(2024-10-03), `@nestjs/platform-fastify` requires **Fastify v4.28.1**, while the latest Fastify version is **5.0.0**. The latest versions of `@fastify/cookie`, `@fastify/csrf-protection`, `@fastify/helmet`, and **@fastify/cors** are not compatible with **Fastify v4.28.1**. Therefore, you need to install the older versions of these packages:

```bash
npm install fastify@4.28.1 @fastify/cookie@9.4.0 @fastify/cors@9.0.1 @fastify/csrf-protection@6.4.1 @fastify/helmet@11.1.1
```