import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ImagesModule } from 'src/file-management/images/images.module';
import { AuthHelper } from './helpers/auth.helper';
import { JwtModule } from '../jwt/jwt.module';
import { EncryptionModule } from '../encryption/encryption.module';
import { Auth2faHelper } from './helpers/auth-2fa.helper';
import { TypeOrmModule } from '@nestjs/typeorm';
import { LoginDevice } from '../accounts/entities/login-device.entity';
import { RefreshTokenService } from './refresh-token.service';
import { AuthCron } from './auth.cron';
import { OtpVerificationPending } from './entities/otp-verification-pending.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      LoginDevice,
      OtpVerificationPending,
    ]),
    ImagesModule,
    JwtModule,
    EncryptionModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthHelper,
    RefreshTokenService,
    Auth2faHelper,
    AuthCron
  ],
  exports: [AuthService, AuthHelper, RefreshTokenService],
})
export class AuthModule { }
