import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { ImagesModule } from 'src/file-management/images/images.module';

@Module({
  imports: [
    ImagesModule,
  ],
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
