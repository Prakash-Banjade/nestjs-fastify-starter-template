import { ApiPropertyOptional } from "@nestjs/swagger";
import { PageOptionsDto } from "./pageOptions.dto";
import { IsEnum, IsOptional, IsString } from "class-validator";

export enum Deleted {
    ONLY = "only",
    NONE = "none",
    ALL = "all",
}

export class QueryDto extends PageOptionsDto {
    @ApiPropertyOptional({ type: String, enum: Deleted, description: "Option for deleted records", default: Deleted.NONE })
    @IsEnum(Deleted, { message: "Invalid deleted option" })
    @IsOptional()
    deleted: Deleted = Deleted.NONE

    @ApiPropertyOptional({ type: String, description: "Search query", default: "" })
    @IsOptional()
    search?: string

    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    skipPagination?: string = 'false';
}