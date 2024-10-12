import { BadRequestException, Inject, Injectable, InternalServerErrorException, NotFoundException, Scope } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { Brackets, DataSource } from 'typeorm';
import { REQUEST } from '@nestjs/core';
import { BaseRepository } from 'src/common/repository/base-repository';
import { FastifyRequest } from 'fastify';
import { UsersQueryDto } from './dto/user-query.dto';
import paginatedData from 'src/utils/paginatedData';
import { User } from './entities/user.entity';
import { applySelectColumns } from 'src/utils/apply-select-cols';
import { userSelectCols } from './helpers/user-select-cols';
import { AuthUser } from 'src/common/types/global.type';
import { Account } from '../accounts/entities/account.entity';
import { ImagesService } from 'src/file-management/images/images.service';

@Injectable({ scope: Scope.REQUEST })
export class UsersService extends BaseRepository {
  constructor(
    private readonly datasource: DataSource,
    @Inject(REQUEST) req: FastifyRequest,
    private readonly imagesService: ImagesService,
  ) { super(datasource, req) }

  private readonly usersRepo = this.datasource.getRepository<User>(User);
  private readonly accountRepo = this.datasource.getRepository<Account>(Account);

  async findAll(queryDto: UsersQueryDto) {
    const queryBuilder = this.usersRepo.createQueryBuilder('user');

    queryBuilder
      .orderBy("user.createdAt", queryDto.order)
      .skip(queryDto.skip)
      .take(queryDto.take)
      .withDeleted()
      .leftJoin("user.account", "account")
      .leftJoin("user.profileImage", "profileImage")
      .andWhere(new Brackets(qb => {
        queryDto.role && qb.andWhere('account.role = :role', { role: queryDto.role });
      }))

    applySelectColumns(queryBuilder, userSelectCols, 'user');

    return paginatedData(queryDto, queryBuilder);
  }

  async findOne(id: string): Promise<User> {
    const existing = await this.usersRepo.findOne({
      where: { id },
      relations: {
        profileImage: true, account: true,
      },
      select: userSelectCols,
    })
    if (!existing) throw new NotFoundException('User not found');

    return existing;
  }

  async getUserByAccountId(accountId: string): Promise<User> {
    const user = await this.usersRepo.findOne({
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
    return await this.getUserByAccountId(currentUser.accountId);
  }

  async update(updateUserDto: UpdateUserDto, currentUser: AuthUser) {
    const existingUser = await this.getUserByAccountId(currentUser.accountId);
    const existingAccount = await this.accountRepo.findOneBy({ id: currentUser.accountId });
    if (!existingAccount) throw new InternalServerErrorException('Unable to update the associated profile. Please contact support.');

    const profileImage = (updateUserDto.profileImageId && (existingUser.profileImage?.id !== updateUserDto.profileImageId || !existingUser.profileImage))
      ? await this.imagesService.findOne(updateUserDto.profileImageId)
      : existingUser.profileImage;

    // update user
    Object.assign(existingUser, {
      ...updateUserDto,
    });

    // assign profile image
    existingUser.profileImage = profileImage;

    await this.usersRepo.save(existingUser);

    Object.assign(existingAccount, {
      firstName: updateUserDto.firstName || existingAccount.firstName,
      lastName: updateUserDto.lastName,
    })

    await this.accountRepo.save(existingAccount);

    return {
      message: 'Profile Updated'
    }
  }

  async remove(id: string) {
    const existingUser = await this.findOne(id);
    await this.usersRepo.softRemove(existingUser);

    return {
      message: 'User removed',
    }
  }
}
