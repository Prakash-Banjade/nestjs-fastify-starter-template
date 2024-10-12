import { Injectable, Logger, LoggerService } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createTransport, Transporter } from 'nodemailer';
import { Account } from 'src/auth-system/accounts/entities/account.entity';
import SMTPTransport from 'nodemailer/lib/smtp-transport';
import { emailConfig, ITemplatedData, ITemplates } from './mail-service.config';
import { readFileSync } from 'fs';
import * as nodemailer from 'nodemailer';
import Handlebars from 'handlebars';
import { join } from 'path';

@Injectable()
export class MailService {
    private readonly loggerService: LoggerService;
    private readonly transport: Transporter<SMTPTransport.SentMessageInfo>;
    private readonly email: string;
    private readonly domain: string;
    private readonly templates: ITemplates;

    constructor(private readonly configService: ConfigService) {
        this.transport = createTransport(emailConfig);
        this.email = `"Nest Fastify" <${emailConfig.auth.user}>`;
        this.domain = this.configService.get<string>('domain');
        this.loggerService = new Logger(MailService.name);

        this.templates = {
            confirmation: MailService.parseTemplate('email-verification-otp.hbs'),
            resetPassword: MailService.parseTemplate('reset-password.hbs'),
        };
    }

    private static parseTemplate(
        templateName: string,
    ): Handlebars.TemplateDelegate<ITemplatedData> {
        const templateText = readFileSync(
            join(__dirname, 'templates', templateName),
            'utf-8',
        );
        return Handlebars.compile<ITemplatedData>(templateText, { strict: true });
    }

    public async sendEmail(
        to: string,
        subject: string,
        html: string,
        log?: string,
    ): Promise<void> {
        const result = await this.transport.sendMail({
            from: this.email,
            to,
            subject,
            html,
        });

        const previewUrl = nodemailer.getTestMessageUrl(result);

        console.log(previewUrl);
    }

    public async sendConfirmationEmail(account: Account, token: string, otp: number) {
        const { email, firstName, lastName } = account;
        const subject = 'Confirm your email';
        const html = this.templates.confirmation({
            name: firstName + ' ' + lastName,
            link: `https://${this.domain}/auth/confirm/${token}`,
            otp: String(otp),
        });
        this.sendEmail(email, subject, html, 'A new confirmation email was sent.');
    }

    public async sendResetPasswordLink(account: Account, token: string) {
        const { email, firstName, lastName } = account;
        const subject = 'Reset your password';
        const html = this.templates.resetPassword({
            name: firstName + ' ' + lastName,
            link: `https://${this.domain}/auth/reset-password/${token}`,
        });
        this.sendEmail(
            email,
            subject,
            html,
            'A new reset password link was sent.',
        );
    }
}