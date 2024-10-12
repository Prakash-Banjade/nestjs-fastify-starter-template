import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpStatus,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  Scope,
  UnauthorizedException,
} from '@nestjs/common';
import { DataSource, Like } from 'typeorm';
import { PasswordChangeRequest } from './entities/password-change-request.entity';
import { EmailVerificationPending } from './entities/email-verification-pending.entity';
import { BaseRepository } from 'src/common/repository/base-repository';
import { REQUEST } from '@nestjs/core';
import { FastifyReply, FastifyRequest } from 'fastify';
import { Account } from '../accounts/entities/account.entity';
import { User } from '../users/entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { AuthUser } from 'src/common/types/global.type';
import { MAX_PREV_PASSWORDS, PASSWORD_SALT_COUNT, Tokens } from 'src/common/CONSTANTS';
import { RegisterDto } from './dto/register.dto';
import { SignInDto } from './dto/signIn.dto';
import { MailService } from 'src/mail/mail.service';
import { AuthHelper } from './helpers/auth.helper';
import { JwtService } from '../jwt/jwt.service';
import { EmailVerificationDto } from './dto/email-verification.dto';
import { CookieSerializeOptions } from '@fastify/cookie';
import { ChangePasswordDto } from './dto/changePassword.dto';
import * as bcrypt from 'bcrypt';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { UpdateEmailDto } from './dto/update-email.dto';

@Injectable({ scope: Scope.REQUEST })
export class AuthService extends BaseRepository {
  constructor(
    private readonly datasource: DataSource,
    @Inject(REQUEST) req: FastifyRequest,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly authHelper: AuthHelper,
  ) { super(datasource, req) }

  private readonly accountsRepo = this.datasource.getRepository<Account>(Account)
  private readonly usersRepo = this.datasource.getRepository<User>(User)
  private readonly emailVerificationPendingRepo = this.datasource.getRepository<EmailVerificationPending>(EmailVerificationPending)
  private readonly passwordChangeRequestRepo = this.datasource.getRepository<PasswordChangeRequest>(PasswordChangeRequest);

  async login(signInDto: SignInDto, req: FastifyRequest, reply: FastifyReply) {
    const existingRefreshCookie = req.cookies?.[Tokens.REFRESH_TOKEN_COOKIE_NAME];

    const foundAccount = await this.authHelper.validateAccount(signInDto.email, signInDto.password);
    if (!foundAccount.isVerified) return await this.authHelper.sendConfirmationEmail(foundAccount);

    const { access_token, refresh_token } = await this.jwtService.getAuthTokens(foundAccount);

    if (existingRefreshCookie) {
      const { value: existingRefreshToken, valid } = req.unsignCookie(existingRefreshCookie);

      const newRefreshTokenArray = valid
        ? (foundAccount?.refreshTokens?.filter((rt) => rt !== existingRefreshToken) ?? [])
        : (foundAccount.refreshTokens ?? [])

      if (existingRefreshToken) reply.clearCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, this.getRefreshCookieOptions()); // CLEAR COOKIE, BCZ A NEW ONE IS TO BE GENERATED

      foundAccount.refreshTokens = [...newRefreshTokenArray];
    }

    foundAccount.refreshTokens = [...(foundAccount.refreshTokens ?? []), refresh_token];

    await this.accountsRepo.save(foundAccount);

    return reply
      .setCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, refresh_token, this.getRefreshCookieOptions())
      .header('Content-Type', 'application/json')
      .send({
        access_token,
      })
  }

  private getRefreshCookieOptions(): CookieSerializeOptions {
    return {
      secure: this.configService.get('NODE_ENV') === 'production',
      httpOnly: true,
      signed: true,
      sameSite: this.configService.get('NODE_ENV') === 'production' ? 'none' : 'lax',
      expires: new Date(Date.now() + (parseInt(this.configService.getOrThrow('REFRESH_TOKEN_EXPIRATION_SEC')) * 1000)),
      path: '/', // necessary to be able to access cookie from out of this route path context, like auth.guard.ts
    }
  }

  async verifyEmail(emailVerificationDto: EmailVerificationDto) {
    const foundRequest = await this.authHelper.verifyEmail(emailVerificationDto);

    // GET ACCOUNT FROM DATABASE
    const foundAccount = await this.accountsRepo.findOneBy({ email: foundRequest.email });
    if (!foundAccount) throw new NotFoundException('Account not found');

    foundAccount.isVerified = true;
    const savedAccount = await this.accountsRepo.save(foundAccount);

    const newUser = this.usersRepo.create({
      account: savedAccount,
    });

    await this.usersRepo.save(newUser);

    await this.emailVerificationPendingRepo.remove(foundRequest); // remove from db

    return {
      message: 'Account verified successfully',
      account: {
        email: savedAccount.email,
        name: savedAccount.firstName + ' ' + savedAccount.lastName,
      },
    };
  }

  async register(registerDto: RegisterDto) {
    const foundAccount = await this.accountsRepo.findOneBy({
      email: registerDto.email,
    });

    if (foundAccount && foundAccount.isVerified) throw new ConflictException('User with this email already exists');

    // handle if the account is not verified
    if (foundAccount && !foundAccount.isVerified) {
      Object.assign(foundAccount, {
        ...registerDto,
      })

      await this.accountsRepo.save(foundAccount);

      return await this.authHelper.sendConfirmationEmail(foundAccount);
    }

    // create new account
    const newAccount = this.accountsRepo.create(registerDto);
    await this.accountsRepo.save(newAccount);

    return await this.authHelper.sendConfirmationEmail(newAccount);
  }

  async refresh(req: FastifyRequest, reply: FastifyReply) {
    reply.clearCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, this.getRefreshCookieOptions()); // a new refresh token is to be generated
    const oldRefreshToken = req.unsignCookie(req.cookies[Tokens.REFRESH_TOKEN_COOKIE_NAME])?.value;

    const account = await this.accountsRepo.findOneBy({ id: req.accountId, refreshTokens: Like(`%${oldRefreshToken}%`) }); // accountId is validated in the refresh token guard
    if (!account) throw new UnauthorizedException('Invalid refresh token');

    const { access_token, refresh_token } = await this.jwtService.getAuthTokens(account);

    const newRefreshTokenArray = account.refreshTokens?.filter((rt) => rt !== oldRefreshToken);
    account.refreshTokens = [...newRefreshTokenArray, refresh_token];

    await this.accountsRepo.save(account);

    return reply
      .setCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, refresh_token, this.getRefreshCookieOptions())
      .header('Content-Type', 'application/json')
      .send({
        access_token,
      })
  }

  async logout(req: FastifyRequest, reply: FastifyReply) {
    const refreshToken = req.unsignCookie(req.cookies[Tokens.REFRESH_TOKEN_COOKIE_NAME])?.value; // validated from refreshtoken guard

    const account = await this.accountsRepo.findOneBy({ id: req.accountId, refreshTokens: Like(`%${refreshToken}%`) });
    if (!account) throw new UnauthorizedException('Invalid refresh token');

    const newRefreshTokenArray = account.refreshTokens?.filter((rt) => rt !== refreshToken);
    account.refreshTokens = newRefreshTokenArray;

    await this.accountsRepo.save(account);

    return reply.clearCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, this.getRefreshCookieOptions()).status(HttpStatus.NO_CONTENT).send();
  }

  async changePassword(changePasswordDto: ChangePasswordDto, currentUser: AuthUser) {
    const account = await this.authHelper.validateAccount(currentUser.email, changePasswordDto.oldPassword);
    if (!account.isVerified) throw new ForbiddenException();

    // check if the new password is
    for (const prevPassword of account.prevPasswords) {
      const isMatch = await bcrypt.compare(changePasswordDto.newPassword, prevPassword);
      if (isMatch) throw new ForbiddenException(`New password cannot be one of the last ${MAX_PREV_PASSWORDS} passwords`)
    }

    account.password = changePasswordDto.newPassword;
    account.prevPasswords.push(bcrypt.hashSync(changePasswordDto.newPassword, PASSWORD_SALT_COUNT));
    account.passwordUpdatedAt = new Date();

    // maintain prev passwords of size MAX_PREV_PASSWORDS
    if (account.prevPasswords?.length > MAX_PREV_PASSWORDS) {
      account.prevPasswords.shift(); // remove the oldest one, index [0]
    }

    await this.accountsRepo.save(account);

    return {
      message: "Password changed"
    }
  }

  async forgotPassword(email: string) {
    const foundAccount = await this.accountsRepo.findOneBy({ email });
    if (!foundAccount) throw new NotFoundException('Account not found');

    const [resetToken, hashedResetToken] = await this.authHelper.getEncryptedHashTokenPair(
      { email: foundAccount.email },
      this.configService.getOrThrow('FORGOT_PASSWORD_SECRET'),
      this.configService.getOrThrow('FORGOT_PASSWORD_EXPIRATION_SEC')
    )

    // existing request
    let changeRequest: PasswordChangeRequest;
    const existingRequest = await this.passwordChangeRequestRepo.findOneBy({ email });
    if (existingRequest) {
      existingRequest.hashedResetToken = hashedResetToken;
      changeRequest = existingRequest;
    } else {
      const passwordChangeRequest = this.passwordChangeRequestRepo.create({
        email: foundAccount.email,
        hashedResetToken,
      });
      changeRequest = passwordChangeRequest;
    }

    await this.passwordChangeRequestRepo.save(changeRequest);

    // send reset password link
    await this.mailService.sendResetPasswordLink(foundAccount, resetToken);

    return {
      message: `Token is valid for ${Number(this.configService.getOrThrow('FORGOT_PASSWORD_EXPIRATION_SEC')) / 60} minutes`,
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { token: providedResetToken, password } = resetPasswordDto;

    // hash the provided token to check in database
    const result = await this.authHelper.verifyEncryptedHashTokenPair<{ email: string }>(providedResetToken, this.configService.getOrThrow('FORGOT_PASSWORD_SECRET'));
    if (!result || !result?.payload || !result?.tokenHash || !result?.payload?.email) throw new BadRequestException('Invalid reset token');

    const { payload, tokenHash } = result;

    // Retrieve the hashed reset token from the database
    const passwordChangeRequest = await this.passwordChangeRequestRepo.findOneBy({ hashedResetToken: tokenHash, email: payload.email });

    if (!passwordChangeRequest) throw new NotFoundException('Invalid reset token');

    // Check if the reset token has expired
    const now = new Date();
    const resetTokenExpiration = new Date(passwordChangeRequest.createdAt);
    resetTokenExpiration.setSeconds(resetTokenExpiration.getSeconds() + parseInt(this.configService.getOrThrow('FORGOT_PASSWORD_EXPIRATION_SEC')));
    if (now > resetTokenExpiration) {
      await this.passwordChangeRequestRepo.remove(passwordChangeRequest);
      throw new BadRequestException('Reset token has expired');
    }

    // retrieve the user from the database
    const account = await this.accountsRepo.findOneBy({ email: passwordChangeRequest.email });
    if (!account) throw new InternalServerErrorException('The requested Account was not available in the database.');

    // check if the new password is one of the last MAX_PREV_PASSWORDS passwords
    for (const prevPassword of account.prevPasswords) {
      const isMatch = await bcrypt.compare(password, prevPassword);
      if (isMatch) throw new ForbiddenException(`New password cannot be one of the last ${MAX_PREV_PASSWORDS} passwords`)
    }

    account.password = password;
    account.prevPasswords.push(bcrypt.hashSync(password, PASSWORD_SALT_COUNT));
    account.passwordUpdatedAt = new Date();

    // maintain prev passwords of size MAX_PREV_PASSWORDS
    if (account.prevPasswords?.length > MAX_PREV_PASSWORDS) {
      account.prevPasswords.shift(); // remove the oldest one, index [0]
    }

    await this.accountsRepo.save(account);

    // clear the reset token from the database
    await this.passwordChangeRequestRepo.remove(passwordChangeRequest);

    // Return success response
    return { message: 'Password reset successful' };
  }

  async updateEmail(updateEmailDto: UpdateEmailDto, currentUser: AuthUser) {
    const account = await this.accountsRepo.findOneBy({ id: currentUser.accountId });
    if (!account) throw new InternalServerErrorException('Unable to update the associated profile. Please contact support.');

    const isPasswordMatch = await bcrypt.compare(updateEmailDto.password, account.password);
    if (!isPasswordMatch) throw new UnauthorizedException('Invalid password');

    account.email = updateEmailDto.newEmail;

    await this.accountsRepo.save(account);

    return {
      message: 'Email updated'
    }
  }
}
