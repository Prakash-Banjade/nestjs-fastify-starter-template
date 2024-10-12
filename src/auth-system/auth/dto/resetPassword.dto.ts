import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString } from "class-validator";

export class ResetPasswordDto {
    @ApiProperty({ type: String, description: 'Password' })
    @IsString()
    @IsNotEmpty()
    password!: string;

    @ApiProperty({ type: String, description: 'Token' })
    @IsString()
    @IsNotEmpty()
    token!: string;
}