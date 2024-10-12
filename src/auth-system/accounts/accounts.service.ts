import { Injectable } from '@nestjs/common';
import { CreateAccountDto } from './dto/create-account.dto';
import { UpdateAccountDto } from './dto/update-account.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Account } from './entities/account.entity';

@Injectable()
export class AccountsService {
  constructor(
    @InjectRepository(Account) private accountsRepo: Repository<Account>,
  ) { }

  async findOne(id: string) {
    const existingAccount = await this.accountsRepo.findOneBy({ id });
    if (!existingAccount) throw new Error('Account not found');

    return existingAccount;
  }
}
