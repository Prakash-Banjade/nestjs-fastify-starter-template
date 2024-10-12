import { ApiProperty, OmitType } from '@nestjs/swagger';
import { CreateImageDto } from './create-image.dto';
import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateImageDto {
    @ApiProperty({ type: String, description: 'Image Name' })
    @IsString()
    @IsNotEmpty()
    name: string
}
