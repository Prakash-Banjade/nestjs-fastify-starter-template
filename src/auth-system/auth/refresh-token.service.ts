import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Inject, Injectable, Scope } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Cache } from "cache-manager";
import { EnvService } from "src/env/env.service";
import { Repository } from "typeorm";
import { LoginDevice } from "../accounts/entities/login-device.entity";
import { FastifyRequest } from "fastify";
import { REQUEST } from "@nestjs/core";

export interface TRefreshToken {
    deviceId: string,
    refreshToken: string,
}

@Injectable({ scope: Scope.REQUEST })
export class RefreshTokenService {
    email: string;
    deviceId: string;

    constructor(
        @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
        @InjectRepository(LoginDevice) private readonly devicesRepo: Repository<LoginDevice>,
        private readonly envService: EnvService,
        @Inject(REQUEST) private req: FastifyRequest
    ) { }

    init({ email, deviceId }: { email?: string, deviceId?: string }) {
        const user = this.req.user;

        this.email = email ?? user?.email;
        this.deviceId = deviceId ?? user?.deviceId;
    }

    async get() {
        const cacheKey = `user:${this.email}:${this.deviceId}`

        const token: string | null = await this.cacheManager.get(cacheKey);

        return token ? JSON.parse(token) as TRefreshToken : null
    }

    async set(refreshToken: string) {
        const cacheKey = `user:${this.email}:${this.deviceId}`

        const refreshTokenPayload: TRefreshToken = {
            deviceId: this.deviceId,
            refreshToken
        }

        await this.cacheManager.set(cacheKey, JSON.stringify(refreshTokenPayload), this.envService.REFRESH_TOKEN_EXPIRATION_SEC * 1000);
    }

    async remove() {
        const cacheKey = `user:${this.email}:${this.deviceId}`

        await this.cacheManager.del(cacheKey);
    }

    async removeAll() {
        const loginDevices = await this.devicesRepo.find({
            where: { account: { email: this.email } },
            select: { deviceId: true }
        });

        const keys = loginDevices.map((device: LoginDevice) => `user:${this.email}:${device.deviceId}`);

        await this.cacheManager.mdel(keys);
    }

    async getAll() {
        const loginDevices = await this.devicesRepo.find({
            where: { account: { email: this.email } },
            select: { deviceId: true }
        });

        const keys = loginDevices.map((device: LoginDevice) => `user:${this.email}:${device.deviceId}`);

        if (!keys?.length) return [];

        const tokens = await this.cacheManager.mget(keys);

        return tokens.map((token: string | null) => token ? JSON.parse(token) as TRefreshToken : null)?.filter(t => !!t);
    }
}