import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { UpdateAccountDto } from './dto/update-account.dto';
import { DataSource } from 'typeorm';
import { Account } from './entities/account.entity';
import { BaseRepository } from 'src/common/repository/base-repository';
import { FastifyRequest } from 'fastify';
import { REQUEST } from '@nestjs/core';
import { ImagesService } from 'src/file-management/images/images.service';
import { AuthUser } from 'src/common/types/global.type';
import { LoginDevice } from './entities/login-device.entity';
import { RefreshTokenService } from '../auth/refresh-token.service';
import { WebAuthnCredential } from '../webAuthn/entities/webAuthnCredential.entity';

@Injectable()
export class AccountsService extends BaseRepository {
  constructor(
    dataSource: DataSource, @Inject(REQUEST) req: FastifyRequest,
    private readonly imagesService: ImagesService,
    private readonly refreshTokenService: RefreshTokenService
  ) { super(dataSource, req) }

  async update(id: string, dto: UpdateAccountDto) {
    const account = await this.getRepository(Account).findOne({
      where: { id },
      relations: { profileImage: true },
      select: { id: true, firstName: true, lastName: true, verifiedAt: true, profileImage: { id: true } }
    });

    if (!account) throw new NotFoundException('No associated account found');

    const image = await this.imagesService.update(account.profileImage?.id, dto.profileImageId);
    if (image !== undefined) account.profileImage = image;

    Object.assign(account, dto)

    account.setLowerCasedFullName();

    await this.getRepository(Account).save(account);
  }

  async getDevices(currentUser: AuthUser) {
    const { accountId } = currentUser;

    const loginDevices = await this.getRepository(LoginDevice).find({
      where: { account: { id: accountId } },
      order: { lastLogin: 'DESC' },
      select: { id: true, deviceId: true, ua: true, firstLogin: true, lastActivityRecord: true },
    });

    this.refreshTokenService.init({});
    const tokens = await this.refreshTokenService.getAll(); // this will return all the refresh tokens of the current user

    return loginDevices
      .map((device: any) => ({
        ...device,
        signedIn: tokens.some((token) => token.deviceId === device.deviceId),
      }));
  }

  async revokeDevice(deviceId: string, currentUser: AuthUser) {
    const { accountId, email, deviceId: currentDeviceId } = currentUser;

    if (deviceId === currentDeviceId) throw new BadRequestException('Cannot revoke current device');

    const device = await this.getRepository(LoginDevice).findOne({
      where: { deviceId, account: { id: accountId } },
      select: { id: true },
    });

    if (device) {
      await this.getRepository(LoginDevice).save({
        ...device,
        isTrusted: false,
      });
    }

    this.refreshTokenService.init({
      deviceId,
      email: email
    });
    await this.refreshTokenService.remove();

    // remove credentials
    await this.getRepository(WebAuthnCredential).delete({ account: { id: accountId } });

    return { message: 'Device signed out' };
  }

  async get2FaStatus(currentUser: AuthUser) {
    const { accountId } = currentUser;

    const account = await this.getRepository(Account).findOne({
      where: { id: accountId },
      select: { id: true, twoFaEnabledAt: true }
    });

    if (!account) throw new NotFoundException('No associated account found');

    return {
      twoFaEnabledAt: account.twoFaEnabledAt
    }
  }

  async toggle2Fa(enable2Fa: boolean, currentUser: AuthUser) {
    const { accountId } = currentUser;

    const account = await this.getRepository(Account).findOne({
      where: { id: accountId },
      select: { id: true, verifiedAt: true, twoFaEnabledAt: true }
    });

    if (!account) throw new NotFoundException('No associated account found');

    account.twoFaEnabledAt = enable2Fa ? new Date() : null;

    await this.getRepository(Account).save(account);

    return;
  }
}
