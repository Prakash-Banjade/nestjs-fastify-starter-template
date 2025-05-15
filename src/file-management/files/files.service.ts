import { Injectable, InternalServerErrorException, NotFoundException, Res } from '@nestjs/common';
import { CreateFileDto } from './dto/create-files.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { File } from './entities/file.entity';
import { In, Repository } from 'typeorm';
import path from 'path';
import { promises as fsPromises, createReadStream } from 'fs';
import { getFileMetadata } from 'src/utils/getFileMetadata';
import { FastifyReply } from 'fastify';
import { EFileMimeType } from 'src/common/types/global.type';
import { EnvService } from 'src/env/env.service';

@Injectable()
export class FilesService {
  constructor(
    @InjectRepository(File) private filesRepository: Repository<File>,
    private readonly envService: EnvService,
  ) { }

  async upload(createFileDto: CreateFileDto) {

    const files: File[] = await Promise.all(createFileDto?.files.map(async (uploadFile) => {
      const metaData = await getFileMetadata(uploadFile);

      return this.filesRepository.create({
        ...metaData,
        name: createFileDto.name || metaData.originalName,
      });
    }));

    await this.filesRepository.save(files);

    return {
      message: 'File(s) Uploaded',
      count: createFileDto.files.length,
      files: files.map(file => ({ id: file.id, url: file.url, originalName: file.originalName }))
    }
  }

  async findAllByIds(ids: string[], mimeType?: EFileMimeType | EFileMimeType[]) {
    const mimeTypeArrayQuery = mimeType ? In(Array.isArray(mimeType) ? mimeType : [mimeType]) : undefined;
    const mimeTypeArrayQueryObject = mimeTypeArrayQuery ? { mimeType: mimeTypeArrayQuery } : {};

    return await this.filesRepository.find({
      where: [
        { id: In(ids), ...mimeTypeArrayQueryObject },
        { url: In(ids), ...mimeTypeArrayQueryObject }
      ],
      select: { id: true }
    })
  }

  async serveFile(filename: string, reply: FastifyReply) {
    const filePath = path.join(process.cwd(), 'public', filename);

    try {
      // 1. Check that the file exists and is readable
      const stats = await fsPromises.stat(filePath);
      if (!stats.isFile()) {
        throw new NotFoundException('File not found');
      }

      // 2. Determine content-type
      const ext = path.extname(filename).substring(1).toLowerCase();
      const contentType = ext === 'pdf'
        ? 'application/pdf'
        : `image/${ext}`;

      // 3. Set headers
      reply
        .header('Content-Type', contentType)
        .header('Content-Length', stats.size.toString())
        .header('Content-Disposition', 'inline')
        .header('Access-Control-Allow-Origin', this.envService.CLIENT_URL)
        .header('Cross-Origin-Resource-Policy', 'cross-origin');

      // 4. Stream the file
      const stream = createReadStream(filePath);
      stream.on('error', err => {
        // Handle streaming errors
        reply.status(500).send('Error reading file');
      });
      reply.send(stream);

    } catch (err: any) {
      if (err.code === 'ENOENT') {
        // File does not exist
        reply.status(404).send('File not found');
      } else if (err instanceof NotFoundException) {
        reply.status(404).send(err.message);
      } else {
        // Other errors (permissions, etc.)
        reply.status(500).send('Internal server error');
      }
    }
  }
}
