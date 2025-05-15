import { BadRequestException, Inject, Injectable, InternalServerErrorException, NotFoundException, Scope } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { Brackets, DataSource } from 'typeorm';
import { REQUEST } from '@nestjs/core';
import { BaseRepository } from 'src/common/repository/base-repository';
import { FastifyRequest } from 'fastify';
import { UsersQueryDto } from './dto/user-query.dto';
import { paginatedRawData } from 'src/utils/paginatedData';
import { User } from './entities/user.entity';
import { userSelectCols } from './helpers/user-select-cols';
import { AuthUser } from 'src/common/types/global.type';
import { Account } from '../accounts/entities/account.entity';
import { AccountsService } from '../accounts/accounts.service';
import { UpdateAccountDto } from '../accounts/dto/update-account.dto';

@Injectable({ scope: Scope.REQUEST })
export class UsersService extends BaseRepository {
  constructor(
    datasource: DataSource, @Inject(REQUEST) req: FastifyRequest,
    private readonly accountsService: AccountsService,

  ) { super(datasource, req) }

  async findAll(queryDto: UsersQueryDto) {
    const queryBuilder = this.getRepository(User).createQueryBuilder('user');

    queryBuilder
      .orderBy("user.createdAt", queryDto.order)
      .offset(queryDto.skip)
      .limit(queryDto.take)
      .leftJoin("user.account", "account")
      .leftJoin("account.branch", "branch")
      .leftJoin("account.profileImage", "profileImage")
      .where(new Brackets(qb => {
        queryDto.search && qb.andWhere("account.lowerCaseFullName ILIKE :search", { search: queryDto.search.toLowerCase() });
        queryDto.role && qb.andWhere('account.role = :role', { role: queryDto.role });
      }))
      .select([
        "user.id as id",
        "profileImage.url as profileImageUrl",
        "account.lowerCaseFullName as fullName",
        "account.email as email",
        "account.role as role",
        "branch.name as branchName",
      ])

    return paginatedRawData(queryDto, queryBuilder);
  }

  async findOne(id: string): Promise<User> {
    const existing = await this.getRepository(User).findOne({
      where: { id },
      relations: {
        account: true,
      },
      select: userSelectCols,
    })
    if (!existing) throw new NotFoundException('User not found');

    return existing;
  }

  async getUserByAccountId(accountId: string): Promise<User> {
    const user = await this.getRepository(User).findOne({
      where: {
        account: { id: accountId }
      },
      relations: {
        account: true
      },
      select: userSelectCols,
    })
    if (!user) throw new NotFoundException('User not found')

    return user;
  }

  async myDetails(currentUser: AuthUser) {
    return this.getRepository(Account).createQueryBuilder('account')
      .leftJoin('account.profileImage', 'profileImage')
      .leftJoin('account.branch', 'branch')
      .where('account.id = :id', { id: currentUser.accountId })
      .select([
        'account.id as id',
        'account.email as email',
        'account.firstName as firstName',
        'account.lastName as lastName',
        'account.role as role',
        'profileImage.url as profileImageUrl',
        'branch.name as branchName',
      ])
      .getRawOne();
  }

  async update(updateUserDto: UpdateUserDto, currentUser: AuthUser) {
    await this.accountsService.update(currentUser.accountId, new UpdateAccountDto(updateUserDto));

    return { message: 'Profile Updated' }
  }
}
