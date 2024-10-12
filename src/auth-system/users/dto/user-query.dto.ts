import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsOptional } from "class-validator";
import { QueryDto } from "src/common/dto/query.dto";
import { Gender, Role } from "src/common/types/global.type";

export class UsersQueryDto extends QueryDto {
    @ApiPropertyOptional({ type: 'string', required: false })
    @IsOptional()
    phone?: string;

    @ApiPropertyOptional({ type: 'enum', enum: Gender })
    @IsOptional()
    gender?: Gender;

    @ApiPropertyOptional({ type: 'string', required: false })
    @IsOptional()
    dob?: string;

    @ApiPropertyOptional({ type: 'enum', enum: Role })
    @IsOptional()
    role: Role
}