import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, IsStrongPassword } from "class-validator";

export class ChangePasswordDto {
    @ApiProperty({ type: String, description: 'Password' })
    @IsString()
    @IsNotEmpty()
    oldPassword!: string;
    
    @ApiProperty({ type: String, description: 'Password' })
    @IsString()
    @IsNotEmpty()
    @IsStrongPassword()
    newPassword!: string;
}