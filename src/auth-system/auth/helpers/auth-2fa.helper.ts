import { Inject, Injectable, Scope, UnauthorizedException } from "@nestjs/common";
import { REQUEST } from "@nestjs/core";
import { FastifyReply, FastifyRequest } from "fastify";
import { Account } from "src/auth-system/accounts/entities/account.entity";
import { BaseRepository } from "src/common/repository/base-repository";
import { DataSource, IsNull, Not } from "typeorm";
import { AuthHelper } from "./auth.helper";
import { EOptVerificationType, OtpVerificationPending } from "../entities/otp-verification-pending.entity";
import { EnvService } from "src/env/env.service";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { MailEvents } from "src/mail/mail.service";
import { AuthService } from "../auth.service";
import * as crypto from 'crypto'
import { RefreshTokenService } from "../refresh-token.service";
import { generateDeviceId } from "src/common/utils";
import { TwoFAMailEventDto } from "src/mail/dto/mail-events.dto";
import { OtpVerificationDto } from "../dto/auth.dto";
import { LoginDevice } from "src/auth-system/accounts/entities/login-device.entity";

@Injectable({ scope: Scope.REQUEST })
export class Auth2faHelper extends BaseRepository {
    constructor(
        dataSource: DataSource, @Inject(REQUEST) req: FastifyRequest,
        private readonly authHelper: AuthHelper,
        private readonly authService: AuthService,
        private readonly envService: EnvService,
        private readonly eventEmitter: EventEmitter2,
        private readonly refreshTokenService: RefreshTokenService,
    ) { super(dataSource, req) }

    async send2faOtp(email: string, req: FastifyRequest) {
        const account = await this.getRepository(Account).findOne({
            where: { email, verifiedAt: Not(IsNull()) },
            select: { id: true, email: true, firstName: true, lastName: true }
        });
        if (!account) throw new UnauthorizedException('Invalid email');

        const deviceId = generateDeviceId(req.headers['user-agent'], req.ip);

        const { otp, encryptedVerificationToken } = await this.authHelper.generateOtp(account, EOptVerificationType.TWOFACTOR_VERIFICATION, deviceId);

        // send mail
        this.eventEmitter.emit(MailEvents.TWOFA_OTP, new TwoFAMailEventDto({
            otp,
            expirationMin: this.envService.TWOFACTOR_VERIFICATION_EXPIRATION_SEC / 60,
            receiverEmail: account.email,
            receiverName: account.firstName + ' ' + account.lastName,
        }));

        return {
            message: "OTP sent",
            token: encryptedVerificationToken,
            expiresIn: this.envService.TWOFACTOR_VERIFICATION_EXPIRATION_SEC
        }
    }

    // async validate2faToken(encryptedToken: string) {
    //     const { payload, error } = await this.authHelper.verifyEncryptedHashTokenPair(encryptedToken, this.envService.TWOFACTOR_VERIFICATION_SECRET);
    //     if (error || !payload) throw new UnauthorizedException('Invalid token');

    //     return { message: "VALID TOKEN" };
    // }

    async verify2faOtp(otpVerificationDto: OtpVerificationDto, req: FastifyRequest, reply: FastifyReply) {
        const deviceId = generateDeviceId(req.headers['user-agent'], req.ip);

        const foundRequest = await this.authHelper.verifyPendingOtp({
            otpVerificationDto,
            type: EOptVerificationType.TWOFACTOR_VERIFICATION,
            deviceId
        });

        const account = await this.getRepository(Account).findOne({
            where: { email: foundRequest.email, verifiedAt: Not(IsNull()) },
            relations: { profileImage: true },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                role: true,
                twoFaEnabledAt: true,
                profileImage: { url: true }
            }
        });
        if (!account) throw new UnauthorizedException('Invalid email');

        // add login device
        const existing = await this.getRepository(LoginDevice).findOne({ // there can be the same device but untrusted, so if yes, update that
            where: { account: { id: account.id }, deviceId },
            select: { id: true }
        });

        if (existing?.id) {
            existing.lastLogin = new Date();
            existing.lastActivityRecord = new Date();
            existing.isTrusted = true;

            await this.getRepository(LoginDevice).save(existing);
        } else {
            await this.getRepository(LoginDevice).save({
                id: existing?.id,
                account,
                deviceId,
                firstLogin: new Date(),
                lastLogin: new Date(),
                lastActivityRecord: new Date(),
                ua: req.headers['user-agent'],
                isTrusted: true
            });
        }

        // remove from db
        await this.getRepository(OtpVerificationPending).remove(foundRequest);

        this.refreshTokenService.init({ email: account.email, deviceId }); // initialize the refresh token instance from here bcz it's not going to happen inside proceedLogin
        return this.authService.proceedLogin({ account, req, reply, checkDevice: false }); // skip device check
    }

    async resend2faOtp(verificationToken: string, req: FastifyRequest) {
        const deviceId = generateDeviceId(req.headers['user-agent'], req.ip);

        const hashedVerificationToken = crypto
            .createHash('sha256')
            .update(verificationToken)
            .digest('hex');

        const foundRequest = await this.getRepository(OtpVerificationPending).findOne({
            where: { hashedVerificationToken },
            select: { email: true }
        });
        if (!foundRequest) throw new UnauthorizedException('Invalid token');

        const account = await this.getRepository(Account).findOne({
            where: { email: foundRequest.email, verifiedAt: Not(IsNull()) },
            select: { id: true, email: true, firstName: true, lastName: true }
        });
        if (!account) throw new UnauthorizedException('Invalid email');

        const { otp, encryptedVerificationToken } = await this.authHelper.generateOtp(account, EOptVerificationType.TWOFACTOR_VERIFICATION, deviceId);

        // send mail
        this.eventEmitter.emit(MailEvents.TWOFA_OTP, new TwoFAMailEventDto({
            otp,
            expirationMin: this.envService.TWOFACTOR_VERIFICATION_EXPIRATION_SEC / 60,
            receiverEmail: account.email,
            receiverName: account.firstName + ' ' + account.lastName,
        }));

        return {
            message: "OTP sent",
            token: encryptedVerificationToken,
            expiresIn: this.envService.TWOFACTOR_VERIFICATION_EXPIRATION_SEC
        }
    }

}