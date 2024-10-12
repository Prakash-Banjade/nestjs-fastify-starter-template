import { Module } from '@nestjs/common';
import { AccountsService } from './accounts.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Account } from './entities/account.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Account]),
  ],
  providers: [AccountsService],
  exports: [AccountsService],
})
export class AccountsModule { }
