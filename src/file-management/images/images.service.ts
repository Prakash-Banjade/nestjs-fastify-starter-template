import { Injectable, NotFoundException, Res } from '@nestjs/common';
import { CreateImageDto } from './dto/create-image.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Image } from './entities/image.entity';
import { Repository } from 'typeorm';
import path from 'path';
import { createReadStream, promises as fsPromises } from 'fs';
import sharp from 'sharp';
import { ImageQueryDto } from './dto/image-query.dto';
import { AuthUser } from 'src/common/types/global.type';
import { getImageMetadata } from 'src/utils/getImageMetadata';
import { FastifyReply } from 'fastify';
import { Account } from 'src/auth-system/accounts/entities/account.entity';

@Injectable()
export class ImagesService {
  constructor(
    @InjectRepository(Image) private imagesRepository: Repository<Image>,
    @InjectRepository(Account) private accountRepository: Repository<Account>,
  ) { }

  async upload(createImageDto: CreateImageDto, currentUser: AuthUser) {
    const account = await this.accountRepository.findOne({
      where: { id: currentUser.accountId },
      select: { id: true }
    })

    const images: Image[] = await Promise.all(createImageDto?.images.map(async (uploadImage) => {
      const metaData = await getImageMetadata(uploadImage);

      return this.imagesRepository.create({
        ...metaData,
        name: createImageDto.name || metaData.originalName,
        uploadedBy: account
      });
    }));

    await this.imagesRepository.save(images);

    return {
      message: 'Image(s) Uploaded',
      files: images.map(image => ({ id: image.id, url: image.url, originalName: image.originalName })),
      count: createImageDto.images.length,
    }
  }

  async findOne(id: string) {
    const existingImage = await this.imagesRepository.findOne({
      where: [
        { id },
        { url: id }
      ],
      select: {
        id: true,
        mimeType: true,
        originalName: true,
      }
    });
    if (!existingImage) throw new NotFoundException('Image not found');

    return existingImage
  }

  async serveImage(filename: string, queryDto: ImageQueryDto, reply: FastifyReply) {
    const imagePath = path.join(process.cwd(), 'public', filename);

    try {
      // Check if the file exists
      await fsPromises.access(imagePath);

      // Create a readable stream from the original image file
      const readStream = createReadStream(imagePath);

      // Handle errors during streaming
      readStream.on('error', (err) => {
        console.error('Error reading the file:', err);
        reply.status(500).send('Error reading the image file');
      });

      // Set the response header for the image type
      reply.header('Content-Type', 'image/webp');

      // Use sharp to transform the image and directly pipe it to reply
      const transform = sharp()
        .webp({ quality: isNaN(Number(queryDto.q)) ? 90 : parseInt(queryDto.q) })
        .resize(isNaN(Number(queryDto.w)) ? undefined : parseInt(queryDto.w));

      // Pipe the read stream into the sharp transform, and then send it
      reply.send(readStream.pipe(transform));

    } catch (err) {
      console.error('File not found or inaccessible:', err);
      reply.status(404).send('Original image not found');
    }
  }

  async update(existingImageId: string | null, newImageId: string | null | undefined): Promise<Image | null> {
    if (!existingImageId && !newImageId) return;

    if ((!existingImageId && newImageId) || (existingImageId && newImageId && (existingImageId !== newImageId))) {
      const image = await this.findOne(newImageId);

      if (existingImageId && existingImageId !== image.id) { // newImageId can be url of existingImageId image, so check if it's not the same before deleting
        await this.imagesRepository.delete({ id: existingImageId });
      }

      return image;
    }

    if (existingImageId && newImageId === null) {
      await this.imagesRepository.delete({ id: existingImageId });
      return null;
    }

    if (existingImageId && (existingImageId === newImageId)) return undefined;
  }
}
