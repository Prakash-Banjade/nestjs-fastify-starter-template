require('dotenv').config()
import { TemplateDelegate } from 'handlebars';

interface IEmailAuth {
    user: string;
    pass: string;
}

export interface IEmailConfig {
    host: string;
    port: number;
    secure: boolean;
    auth: IEmailAuth;
}

export const emailConfig: IEmailConfig = {
    host: process.env.MAIL_OUTGOING_SERVER,
    port: parseInt(process.env.MAIL_SMTP_PORT, 10),
    secure: process.env.MAIL_SMTP_PORT === '465',
    auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
    },
}

export interface ITemplatedData {
    name: string;
    link: string;
}


export interface ITemplates {
    confirmation: TemplateDelegate<ITemplatedData & { otp: string }>;
    resetPassword: TemplateDelegate<ITemplatedData>;
}