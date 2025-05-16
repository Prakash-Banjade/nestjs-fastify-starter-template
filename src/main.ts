import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { AllExceptionsFilter } from './common/filters/all-exception.filter';
import { setupSwagger } from './config/swagger.config';
import { ValidationPipe } from '@nestjs/common';
import fastifyCookie from '@fastify/cookie';
import { ConfigService } from '@nestjs/config';
import fastifyHelmet from '@fastify/helmet';
import fastifyCsrfProtection from '@fastify/csrf-protection';
import fastifyCors from '@fastify/cors';
import fastifyMultipart from '@fastify/multipart';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({}),
  );

  const configService = app.get(ConfigService);

  app.register(fastifyCookie, {
    secret: configService.get<string>('COOKIE_SECRET'),
  });

  app.register(fastifyHelmet);
  app.register(fastifyCsrfProtection, { cookieOpts: { signed: true } });
  app.register(fastifyMultipart);

  app.register(fastifyCors, {
    credentials: true,
    origin: configService.get<string>('CLIENT_URL'),
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    optionsSuccessStatus: 200,
    preflightContinue: false, // enforce CORS policy consistently across the application's endpoints.
    methods: ['GET', 'POST', 'DELETE', 'PATCH'],
  });

  // global exception filter
  const { httpAdapter } = app.get(HttpAdapterHost);
  app.useGlobalFilters(new AllExceptionsFilter(httpAdapter));

  // global validation pipe
  app.useGlobalPipes(new ValidationPipe({
    transform: true,
    whitelist: true,
  }));

  // swagger docs setup
  setupSwagger(app);

  app.setGlobalPrefix('api');

  await app.listen(3001);
  console.log(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();
