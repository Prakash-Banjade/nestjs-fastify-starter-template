import { CookieSerializeOptions } from '@fastify/csrf-protection';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService as JwtSer } from '@nestjs/jwt';
import { Tokens } from 'src/common/CONSTANTS';
import { AuthUser } from 'src/common/types/global.type';
import { Account } from '../accounts/entities/account.entity';

@Injectable()
export class JwtService {
    constructor(
        private readonly jwtService: JwtSer,
        private readonly configService: ConfigService,
    ) { }

    private readonly ACCESS_TOKEN_SECRET = this.configService.getOrThrow<string>('ACCESS_TOKEN_SECRET');
    private readonly ACCESS_TOKEN_EXPIRATION_SEC = +this.configService.getOrThrow<number>('ACCESS_TOKEN_EXPIRATION_SEC');
    private readonly REFRESH_TOKEN_SECRET = this.configService.getOrThrow<string>('REFRESH_TOKEN_SECRET');
    private readonly REFRESH_TOKEN_EXPIRATION_SEC = +this.configService.getOrThrow<number>('REFRESH_TOKEN_EXPIRATION_SEC');

    async createAccessToken(payload: AuthUser): Promise<string> {
        return await this.jwtService.signAsync(payload, {
            secret: this.ACCESS_TOKEN_SECRET,
            expiresIn: this.ACCESS_TOKEN_EXPIRATION_SEC,
        });
    }

    async createRefreshToken(payload: Pick<AuthUser, 'accountId'>): Promise<string> {
        return await this.jwtService.signAsync(
            { accountId: payload.accountId },
            {
                secret: this.REFRESH_TOKEN_SECRET,
                expiresIn: this.REFRESH_TOKEN_EXPIRATION_SEC,
            },
        );
    }

    async getAuthTokens(account: Account) {
        const payload: AuthUser = {
            email: account.email,
            accountId: account.id,
            role: account.role,
        };

        const access_token = await this.createAccessToken(payload);
        const refresh_token = await this.createRefreshToken(payload);

        return { access_token, refresh_token };
    }
}
