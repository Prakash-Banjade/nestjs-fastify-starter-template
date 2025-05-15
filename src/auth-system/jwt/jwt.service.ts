import { Injectable } from '@nestjs/common';
import { JwtService as JwtSer } from '@nestjs/jwt';
import { AuthUser } from 'src/common/types/global.type';
import { Account } from '../accounts/entities/account.entity';
import { FastifyRequest } from 'fastify';
import { generateDeviceId } from 'src/common/utils';
import { EnvService } from 'src/env/env.service';

@Injectable()
export class JwtService {
    constructor(
        private readonly jwtService: JwtSer,
        private readonly envService: EnvService,
    ) { }

    async createAccessToken(payload: AuthUser): Promise<string> {
        return await this.jwtService.signAsync(payload, {
            secret: this.envService.ACCESS_TOKEN_SECRET,
            expiresIn: this.envService.ACCESS_TOKEN_EXPIRATION_SEC,
        });
    }

    async createRefreshToken(payload: Pick<AuthUser, 'accountId'>): Promise<string> {
        return await this.jwtService.signAsync(
            { accountId: payload.accountId },
            {
                secret: this.envService.REFRESH_TOKEN_SECRET,
                expiresIn: this.envService.REFRESH_TOKEN_EXPIRATION_SEC,
            },
        );
    }

    async getSudoAccessToken(accountId: string): Promise<string> {
        return this.jwtService.signAsync(
            { accountId },
            {
                secret: this.envService.SUDO_ACCESS_TOKEN_SECRET,
                expiresIn: this.envService.SUDO_ACCESS_TOKEN_EXPIRATION_SEC,
            }
        );
    }

    async getAuthTokens(account: Account, req: FastifyRequest) {
        const deviceId = generateDeviceId(req.headers['user-agent'], req.ip);

        const payload: AuthUser = {
            firstName: account.firstName,
            lastName: account.lastName,
            profileImage: account.profileImage?.url,
            email: account.email,
            accountId: account.id,
            role: account.role,
            deviceId,
        };

        const access_token = await this.createAccessToken(payload);
        const refresh_token = await this.createRefreshToken(payload);

        return { access_token, refresh_token };
    }
}
