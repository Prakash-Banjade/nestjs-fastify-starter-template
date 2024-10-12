import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString } from "class-validator";

export class VerifyResetTokenDto {
    @ApiProperty({ type: String, description: 'Token' })
    @IsString()
    @IsNotEmpty()
    token!: string;
}