import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res, UseGuards, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiConsumes, ApiTags } from '@nestjs/swagger';
import { FastifyReply, FastifyRequest } from 'fastify';
import { RegisterDto } from './dto/register.dto';
import { SignInDto } from './dto/signIn.dto';
import { EmailVerificationDto } from './dto/email-verification.dto';
import { Public } from 'src/common/decorators/setPublicRoute.decorator';
import { TransactionInterceptor } from 'src/common/interceptors/transaction.interceptor';
import { FormDataRequest } from 'nestjs-form-data';
import { RefreshTokenGuard } from 'src/common/guards/refresh-token.guard';
import { ChangePasswordDto } from './dto/changePassword.dto';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { AuthUser } from 'src/common/types/global.type';
import { PasswordChangeRequestDto } from './dto/password-change-req.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { UpdateEmailDto } from './dto/update-email.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Public()
    @Post('login')
    @UseInterceptors(TransactionInterceptor)
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    login(
        @Body() signInDto: SignInDto,
        @Req() request: FastifyRequest,
        @Res({ passthrough: true }) response: FastifyReply,
    ) {
        return this.authService.login(signInDto, request, response);
    }

    @Public()
    @Post('refresh')
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    @HttpCode(HttpStatus.OK)
    @UseGuards(RefreshTokenGuard)
    refresh(@Req() req: FastifyRequest, @Res({ passthrough: true }) res: FastifyReply) {
        return this.authService.refresh(req, res);
    }

    @Public()
    @Post('register')
    @UseInterceptors(TransactionInterceptor)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @Public()
    @Post('verify-email')
    @UseInterceptors(TransactionInterceptor)
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    verifyEmail(@Body() emailVerificationDto: EmailVerificationDto) {
        return this.authService.verifyEmail(emailVerificationDto);
    }

    @Post('logout')
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    @UseGuards(RefreshTokenGuard)
    logout(@Req() req: FastifyRequest, @Res({ passthrough: true }) res: FastifyReply) {
        return this.authService.logout(req, res);
    }

    @Post('change-password')
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    changePassword(@Body() changePasswordDto: ChangePasswordDto, @CurrentUser() currentUser: AuthUser) {
        return this.authService.changePassword(changePasswordDto, currentUser);
    }


    @Public()
    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    forgotPassword(@Body() { email }: PasswordChangeRequestDto) {
        return this.authService.forgotPassword(email)
    }

    @Public()
    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
        return this.authService.resetPassword(resetPasswordDto);
    }

    @Post('update-email')
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    updateEmail(@Body() updateEmailDto: UpdateEmailDto, @CurrentUser() currentUser: AuthUser) {
        return this.authService.updateEmail(updateEmailDto, currentUser);
    }
}
