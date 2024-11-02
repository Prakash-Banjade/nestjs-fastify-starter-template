import { Module } from '@nestjs/common';
import { ImagesModule } from './images/images.module';
import { FilesModule } from './files/files.module';

@Module({
    imports: [
        ImagesModule,
        FilesModule,
    ],
})
export class FileManagementModule {}
