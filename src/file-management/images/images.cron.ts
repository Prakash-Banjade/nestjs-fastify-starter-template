import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { IsNull, Repository } from "typeorm";
import { Image } from "./entities/image.entity";
import { Cron, CronExpression } from "@nestjs/schedule";
import fs from 'fs';
import path from "path";

@Injectable()
export class ImagesCron {
    constructor(
        @InjectRepository(Image) private readonly imagesRepo: Repository<Image>,
    ) { }

    @Cron(CronExpression.EVERY_WEEKEND)
    async removeUnusedImages() {
        console.log("Removing unused images...")

        const unusedImagesInDb = await this.imagesRepo.find({
            where: {
                account_profileImage: IsNull(),
            },
            select: { id: true, url: true }
        });

        const imageFileName = unusedImagesInDb.map(image => image.url.split('/').pop());

        // REMOVE FROM DISK STORAGE
        imageFileName.forEach(filename => {
            if (filename) {
                const imagePath = path.join(process.cwd(), 'public', filename);

                if (fs.existsSync(imagePath)) {
                    fs.unlinkSync(imagePath);
                }
            }
        });

        // REMOVE FROM DB
        await this.imagesRepo.remove(unusedImagesInDb);

        console.log(`Removed unused images. Count: ${unusedImagesInDb.length}`);
    }
}