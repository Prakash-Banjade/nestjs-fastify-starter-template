import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class UpdateEmailDto {
    @IsEmail()
    @ApiProperty({ type: String, description: 'New email' })
    newEmail: string;

    @ApiProperty({ type: String, description: 'Password' })
    @IsString()
    @IsNotEmpty()
    password: string;
}