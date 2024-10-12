import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsDateString, IsEnum, IsNotEmpty, IsOptional, IsPhoneNumber, IsString, IsUUID, Length } from "class-validator";
import { Gender } from "src/common/types/global.type";

export class UpdateUserDto {
    @ApiPropertyOptional({ type: 'string', description: 'First name of the user' })
    @IsString()
    @IsNotEmpty()
    @Length(2)
    @IsOptional()
    firstName?: string;

    @ApiPropertyOptional({ type: 'string', description: 'Last name of the user' })
    @IsString()
    @IsOptional()
    lastName?: string = '';

    @ApiPropertyOptional({ type: 'string', description: 'A valid UAE based phone number' })
    @IsPhoneNumber()
    @IsOptional()
    phone?: string

    @ApiPropertyOptional({ type: 'enum', enum: Gender, enumName: 'Gender' })
    @IsEnum(Gender)
    @IsOptional()
    gender?: Gender

    @ApiPropertyOptional({ type: 'string', format: 'date-time', description: 'Date of Birth' })
    @IsDateString({ strict: true })
    @IsOptional()
    dob?: string

    @ApiPropertyOptional({ type: 'string', description: 'Profile image url' })
    @IsOptional()
    @IsUUID()
    profileImageId?: string;
}
