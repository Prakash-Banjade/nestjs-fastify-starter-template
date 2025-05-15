import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { Cron, CronExpression } from "@nestjs/schedule";
import fs from 'fs';
import path from "path";
import { File } from "./entities/file.entity";

@Injectable()
export class FilesCron {
    constructor(
        @InjectRepository(File) private readonly filesRepo: Repository<File>,
    ) { }

    @Cron(CronExpression.EVERY_WEEKEND)
    async removeUnusedFiles() {
        console.log("Removing unused files...")

        const unusedFilesInDb = await this.filesRepo.find({
            where: {},
            select: { id: true, url: true }
        });

        const fileFileName = unusedFilesInDb.map(file => file.url.split('/').pop());

        // REMOVE FROM DISK STORAGE
        fileFileName.forEach(filename => {
            const filePath = path.join(process.cwd(), 'public', filename);

            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        });

        // REMOVE FROM DB
        await this.filesRepo.remove(unusedFilesInDb);

        console.log(`Removed unused files. Count: ${unusedFilesInDb.length}`);
    }
}