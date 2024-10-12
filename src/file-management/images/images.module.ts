import { Global, Module } from '@nestjs/common';
import { ImagesService } from './images.service';
import { ImagesController } from './images.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Image } from './entities/image.entity';
import { AccountsModule } from 'src/auth-system/accounts/accounts.module';

Global()
@Module({
  imports: [
    TypeOrmModule.forFeature([
      Image,
    ]),
    AccountsModule,
  ],
  controllers: [ImagesController],
  providers: [ImagesService],
  exports: [ImagesService],
})
export class ImagesModule { }
