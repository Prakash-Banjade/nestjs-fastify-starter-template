import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsEnum, IsOptional, IsString } from "class-validator";

export class ImageQueryDto {
    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    w?: string;

    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    q?: string;

    @ApiPropertyOptional({ enum: ['true', 'false'] })
    @IsString()
    @IsOptional()
    @IsEnum(['true', 'false'])
    thumbnail?: string;
}