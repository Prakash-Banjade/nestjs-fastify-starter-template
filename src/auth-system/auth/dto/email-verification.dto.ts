import { BadRequestException } from "@nestjs/common";
import { ApiProperty } from "@nestjs/swagger";
import { Transform } from "class-transformer";
import { IsInt, IsNotEmpty, IsString } from "class-validator";

export class EmailVerificationDto {
    @ApiProperty({ type: Number })
    @Transform(({ value }) => {
        if (isNaN(parseInt(value))) throw new BadRequestException('Invalid OTP')
        return parseInt(value)
    })
    @IsInt()
    @IsNotEmpty()
    otp: number

    @ApiProperty({ type: String })
    @IsString()
    @IsNotEmpty()
    verificationToken: string;
}