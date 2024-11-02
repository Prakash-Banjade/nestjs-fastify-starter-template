import path from 'path';
import fs from 'fs';
import { MemoryStoredFile } from 'nestjs-form-data';
import { generateSlug } from './generateSlug';

export interface FileMetadata {
    mimeType: string;
    size: number;
    url: string;
    format: string;
    originalName: string;
}

export async function getFileMetadata(memoryStoredFile: MemoryStoredFile) {
    // Use process.cwd() to get the root directory of the project, else nestjs will use the dist folder if you use __dirname
    const uploadDir = path.join(process.cwd(), 'public');
    const fileNameSlug = generateSlug(memoryStoredFile.originalName, true);

    // file extension
    const format = path.extname(memoryStoredFile.originalName).substring(1);

    let metadata: FileMetadata = {
        mimeType: memoryStoredFile.mimetype,
        format: format,
        size: memoryStoredFile.size,
        url: process.env.BACKEND_URL + '/api/upload/files/get-file/' + fileNameSlug + '.' + format,
        originalName: memoryStoredFile.originalName
    };

    if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
    }

    const filePath = path.join(uploadDir, fileNameSlug + '.' + format);

    // Save the file to the file system
    fs.writeFile(filePath, memoryStoredFile.buffer, (err) => {
        if (err) {
            console.error('Error saving file:', err);
            throw err;
        } else {
            console.log('File saved successfully:', filePath);
        }
    });

    return metadata;
}
