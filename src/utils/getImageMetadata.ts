import * as path from 'path';
import fs from 'fs';
import { MemoryStoredFile } from 'nestjs-form-data';
import sharp from 'sharp';
import { generateSlug } from './generateSlug';

export interface ImageMetadata {
    width: number;
    height: number;
    mimeType: string;
    size: number;
    url: string;
    format: string;
    space: string;
    originalName: string;
}

export async function getImageMetadata(memoryStoredFile: MemoryStoredFile) {
    // Use process.cwd() to get the root directory of the project, else nestjs will use the dist folder if you use __dirname
    const uploadDir = path.join(process.cwd(), 'public');
    const fileNameSlug = generateSlug(memoryStoredFile.originalName?.split('.').slice(0, -1).join('.'), true);

    let metadata: ImageMetadata = {
        width: 0,
        height: 0,
        mimeType: memoryStoredFile.mimetype,
        size: memoryStoredFile.size,
        url: process.env.BACKEND_URL + '/api/upload/images/get-image/' + fileNameSlug + '.webp',
        format: 'webp',  // Set format to webp
        space: '',
        originalName: memoryStoredFile.originalName
    };

    const md = await sharp(memoryStoredFile.buffer).metadata();
    metadata.width = md.width;
    metadata.height = md.height;
    metadata.space = md.space;

    if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
    }

    const filePath = path.join(uploadDir, fileNameSlug + '.webp');

    // Save the file in WebP format
    const webpBuffer = await sharp(memoryStoredFile.buffer).webp().toBuffer();
    fs.writeFile(filePath, webpBuffer, (err) => {
        if (err) {
            console.error('Error saving file:', err);
            throw err;
        }
    });

    return metadata;
}
