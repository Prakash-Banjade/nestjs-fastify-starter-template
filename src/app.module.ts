import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from './datasource/typeorm.module';
import { AuthSystemModule } from './auth-system/auth-system.module';
import { FileManagementModule } from './file-management/file-management.module';
import { MemoryStoredFile, NestjsFormDataModule } from 'nestjs-form-data';
import { MailModule } from './mail/mail.module';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AuthGuard } from './common/guards/auth.guard';
import { AbilitiesGuard } from './common/guards/abilities.guard';
import { createKeyv } from '@keyv/redis';
import { CacheModule } from '@nestjs/cache-manager';
import { EnvModule } from './env/env.module';
import { ScheduleModule } from '@nestjs/schedule';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { CaslModule } from './auth-system/casl/casl.module';

@Module({
  imports: [
    EnvModule,
    NestjsFormDataModule.config({
      storage: MemoryStoredFile,
      isGlobal: true,
      fileSystemStoragePath: 'public',
      autoDeleteFile: false,
      limits: {
        files: 10,
        fileSize: 5 * 1024 * 1024,
      },
      cleanupAfterSuccessHandle: false, // !important
    }),
    ThrottlerModule.forRoot([{
      ttl: 1000, // 5 req per second
      limit: 5,
    }]),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      isGlobal: true,
      useFactory: async (configService: ConfigService) => {
        return {
          stores: [createKeyv(configService.getOrThrow('REDIS_URL'))],
        };
      },
      inject: [ConfigService],
    }),
    CaslModule,
    EventEmitterModule.forRoot(),
    ScheduleModule.forRoot(),
    TypeOrmModule,
    AuthSystemModule,
    FileManagementModule,
    MailModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard, // global rate limiting, but can be overriden in route level
    },
    {
      provide: APP_GUARD,
      useClass: AuthGuard, // global auth guard
    },
    {
      provide: APP_GUARD,
      useClass: AbilitiesGuard, // global ability guard
    },
  ],
})
export class AppModule { }
