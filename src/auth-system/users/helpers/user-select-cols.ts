import { FindOptionsSelect } from "typeorm";
import { User } from "../entities/user.entity";

export const userSelectCols: FindOptionsSelect<User> = {
    id: true,
    dob: true,
    gender: true,
    phone: true,
    createdAt: true,
    profileImage: {
        id: true,
        url: true,
    },
    account: {
        firstName: true,
        lastName: true,
        email: true,
        role: true,
    }
}