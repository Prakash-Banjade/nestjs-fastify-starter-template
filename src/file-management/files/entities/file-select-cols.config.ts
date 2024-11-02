import { FindOptionsSelect } from "typeorm";
import { File } from "./file.entity";

export const fileSelectColumns: FindOptionsSelect<File> = {
    id: true,
    url: true,
    format: true,
    originalName: true,
    name: true,
    mimeType: true,
    createdAt: true,
}