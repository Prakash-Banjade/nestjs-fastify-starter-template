import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsOptional, IsString, IsStrongPassword, Length, Matches } from "class-validator";
import { NAME_REGEX } from "src/common/CONSTANTS";

export class RegisterDto {
    @ApiProperty({ type: 'string', description: 'First name of the user' })
    @IsString()
    @IsNotEmpty()
    @Length(2)
    @Matches(NAME_REGEX, {
        message: 'Name must not have special characters'
    })
    firstName!: string;

    @ApiProperty({ type: 'string', description: 'Last name of the user' })
    @IsString()
    @Length(2)
    @IsOptional()
    @Matches(NAME_REGEX, {
        message: 'Name must not have special characters'
    })
    lastName?: string;

    @ApiProperty({ type: 'string', format: 'email', description: 'Valid email' })
    @IsEmail()
    @IsNotEmpty()
    email!: string;

    @ApiProperty({ type: 'string', description: 'Enter a strong password' })
    @IsString()
    @IsStrongPassword()
    password!: string;
}