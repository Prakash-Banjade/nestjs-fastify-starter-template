import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class PasswordChangeRequestDto {
    @IsNotEmpty()
    @IsEmail()
    email!: string;

    @IsOptional()
    @IsString()
    cms: string;
}