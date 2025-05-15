import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsNotEmpty, IsOptional, IsString, IsUUID, Length, Matches } from "class-validator";
import { NAME_REGEX, NAME_WITH_SPACE_REGEX } from "src/common/CONSTANTS";

export class UpdateUserDto {
    @ApiPropertyOptional({ type: 'string', description: 'First name of the user' })
    @IsString()
    @IsNotEmpty()
    @Length(2)
    @Matches(NAME_REGEX, { message: 'Name can have only alphabets' })
    @IsOptional()
    firstName?: string;

    @ApiPropertyOptional({ type: 'string', description: 'Last name of the user' })
    @IsString()
    @IsOptional()
    @Matches(NAME_WITH_SPACE_REGEX, { message: 'Name can have only alphabets and spaces' })
    lastName?: string = '';

    @ApiPropertyOptional({ type: 'string', description: 'Profile image url' })
    @IsOptional()
    @IsUUID()
    profileImageId?: string;
}
