import { BadRequestException, Inject, Injectable, NotFoundException, Scope, UnauthorizedException } from "@nestjs/common";
import { Account } from "src/auth-system/accounts/entities/account.entity";
import { MailService } from "src/mail/mail.service";
import { generateOtp } from "src/utils/generateOPT";
import * as crypto from 'crypto'
import { BaseRepository } from "src/common/repository/base-repository";
import { DataSource } from "typeorm";
import { FastifyRequest } from "fastify";
import { REQUEST } from "@nestjs/core";
import { EmailVerificationPending } from "../entities/email-verification-pending.entity";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { EmailVerificationDto } from "../dto/email-verification.dto";
import * as bcrypt from 'bcrypt';
import { EncryptionService } from "src/auth-system/encryption/encryption.service";

@Injectable({ scope: Scope.REQUEST })
export class AuthHelper extends BaseRepository {
    constructor(
        private readonly datasource: DataSource,
        @Inject(REQUEST) req: FastifyRequest,
        private readonly mailService: MailService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        private readonly encryptionService: EncryptionService,
    ) {
        super(datasource, req);
    }

    private readonly emailVerificationPendingRepo = this.datasource.getRepository<EmailVerificationPending>(EmailVerificationPending)
    private readonly accountsRepo = this.datasource.getRepository<Account>(Account);

    /**
     * Verification token generation:
     * 
     * 1. Generate a jwt token with email as payload
     * 2. Encrypt the jwt token
     * 3. Hash the encrypted token
     * 4. Save the hashed token in db
     * 5. Send the encrypted token to the user's email
     */
    async sendConfirmationEmail(account: Account) {
        const otp = generateOtp();
        const verificationToken = await this.jwtService.signAsync(
            { email: account.email },
            {
                secret: this.configService.getOrThrow('EMAIL_VERIFICATION_SECRET'),
                expiresIn: parseInt(this.configService.getOrThrow('EMAIL_VERIFICATION_EXPIRATION_SEC')),
            }
        );

        const encryptedVerificationToken = this.encryptionService.encrypt(verificationToken);

        const hashedVerificationToken = crypto
            .createHash('sha256')
            .update(encryptedVerificationToken)
            .digest('hex');

        // check for existing verification pending, if yes, remove
        const existingVerificationRequest = await this.emailVerificationPendingRepo.findOneBy({ email: account.email });

        if (existingVerificationRequest) { // update the existing one
            Object.assign(existingVerificationRequest, {
                otp: String(otp),  // opt is saved as hash in db, logic is implemented in email-verification-pending.entity.ts
                hashedVerificationToken,
            })

            await this.emailVerificationPendingRepo.save(existingVerificationRequest);
        } else { // create new one
            const emailVerificationPending = this.emailVerificationPendingRepo.create({
                email: account.email,
                otp: String(otp),
                hashedVerificationToken,
            });
            await this.emailVerificationPendingRepo.save(emailVerificationPending);
        }

        await this.mailService.sendConfirmationEmail(account, encryptedVerificationToken, otp);

        return {
            message: "An OTP has been sent to your email. Please use the OTP to verify your account."
        }
    }

    async verifyEmail(emailVerificationDto: EmailVerificationDto): Promise<EmailVerificationPending> {
        const { otp, verificationToken } = emailVerificationDto;

        let payload: { email: string };
        try {
            const decryptedToken = this.encryptionService.decrypt(verificationToken);
            // verify jwt token
            payload = await this.jwtService.verifyAsync(decryptedToken, {
                secret: this.configService.get('EMAIL_VERIFICATION_SECRET'),
            });
        } catch {
            throw new BadRequestException('Invalid token received')
        }

        const foundRequest = await this.emailVerificationPendingRepo.findOneBy({ email: payload.email })

        const verificationTokenHash = crypto
            .createHash('sha256')
            .update(verificationToken) // this is supposed to be encrypted token, if not, it's invalid
            .digest('hex')

        // comapre the token has with found request hash
        if (verificationTokenHash !== foundRequest.hashedVerificationToken) throw new BadRequestException('Invalid token received');

        // CHECK IF OTP IS VALID
        const isOtpValid = bcrypt.compareSync(String(otp), foundRequest.otp);
        if (!isOtpValid) throw new BadRequestException('Invalid OTP');

        // check if otp has expired
        const now = new Date();
        const otpExpiration = new Date(foundRequest.createdAt);
        otpExpiration.setSeconds(otpExpiration.getSeconds() + this.configService.getOrThrow('EMAIL_VERIFICATION_EXPIRATION_SEC'));
        if (now > otpExpiration) {
            await this.emailVerificationPendingRepo.remove(foundRequest); // remove from database
            throw new BadRequestException('OTP has expired');
        }

        return foundRequest;
    }

    /**
     * Returns Account object if credentials are valid
     * 
     * Note: Doesn't check if the account is verified
     */
    async validateAccount(email: string, password: string): Promise<Account> {
        const foundAccount = await this.accountsRepo.findOneBy({ email });

        if (!foundAccount) throw new UnauthorizedException('Invalid email. Proceed to sign up.');

        const isPasswordValid = await bcrypt.compare(
            password,
            foundAccount.password,
        );

        if (!isPasswordValid) throw new UnauthorizedException('Invalid password')

        return foundAccount;
    }

    /**
     * Generates a token pair [encrypted, hashedEncryptedToken] for the provided payload with the provided secret and expiration
     * 
     * @returns [encryptedToken, hashedEncryptedToken]
     */
    async getEncryptedHashTokenPair(payload: any, secret: string, expiration: number): Promise<[string, string]> {
        const token = await this.jwtService.signAsync(
            payload,
            {
                secret: this.configService.getOrThrow('EMAIL_VERIFICATION_SECRET'),
                expiresIn: parseInt(this.configService.getOrThrow('EMAIL_VERIFICATION_EXPIRATION_SEC')),
            }
        );

        const encryptedToken = this.encryptionService.encrypt(token);

        const hashedToken = crypto
            .createHash('sha256')
            .update(encryptedToken)
            .digest('hex');

        return [encryptedToken, hashedToken];
    }

    async verifyEncryptedHashTokenPair<T>(encryptedToken: string, secret: string): Promise<{ payload: T; tokenHash: string } | null> {
        const tokenHash = crypto
            .createHash('sha256')
            .update(encryptedToken)
            .digest('hex');

        try {
            const decryptedToken = this.encryptionService.decrypt(encryptedToken);
            const payload = await this.jwtService.verifyAsync(decryptedToken, { // verify if the jwt is valid
                secret,
            });

            return { payload, tokenHash };
        } catch (e) {
            return null;
        }
    }
}