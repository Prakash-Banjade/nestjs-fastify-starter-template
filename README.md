# NestJS Fastify Starter Template

Focuses on the following:
- Authentication and Authorization
- JWT Strategy
- Encryption and Hashing of Tokens
- Mail Service

### Version Compatibility Note
As of today(2024-10-03), `@nestjs/platform-fastify` requires **Fastify v4.28.1**, while the latest Fastify version is **5.0.0**. The latest versions of `@fastify/cookie`, `@fastify/csrf-protection`, `@fastify/helmet`, and **@fastify/cors** are not compatible with **Fastify v4.28.1**. Therefore, you need to install the older versions of these packages:

```bash
npm install fastify@4.28.1 @fastify/cookie@9.4.0 @fastify/cors@9.0.1 @fastify/csrf-protection@6.4.1 @fastify/helmet@11.1.1
```

### Environment Variables

Create a `.env` file in the root directory of the project and add the following variables:

```bash
DATABASE_URL=

ACCESS_TOKEN_SECRET=
ACCESS_TOKEN_EXPIRATION_SEC=
REFRESH_TOKEN_SECRET=
REFRESH_TOKEN_EXPIRATION_SEC=
COOKIE_SECRET=

EMAIL_VERIFICATION_SECRET=
EMAIL_VERIFICATION_EXPIRATION_SEC=

FORGOT_PASSWORD_SECRET=
FORGOT_PASSWORD_EXPIRATION_SEC=

CLIENT_URL=

AES_KEY=
AES_IV=

NODE_ENV=

MAIL_OUTGOING_SERVER=
MAIL_SMTP_PORT=
MAIL_USERNAME=
MAIL_PASSWORD=
```