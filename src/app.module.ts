import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from './datasource/typeorm.module';
import { AuthSystemModule } from './auth-system/auth-system.module';
import { FileManagementModule } from './file-management/file-management.module';
import { MemoryStoredFile, NestjsFormDataModule } from 'nestjs-form-data';
import { MailModule } from './mail/mail.module';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AuthGuard } from './common/guards/auth.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
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
  ],
})
export class AppModule { }
