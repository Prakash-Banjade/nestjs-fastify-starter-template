import { ApiProperty, OmitType } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateFileDto {
    @ApiProperty({ type: String, description: 'File Name' })
    @IsString()
    @IsNotEmpty()
    name: string
}
