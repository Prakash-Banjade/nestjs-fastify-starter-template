import { Column, Entity, JoinColumn, OneToOne } from "typeorm";
import { Gender } from "src/common/types/global.type";
import { BaseEntity } from "src/common/entities/base.entity";
import { Account } from "src/auth-system/accounts/entities/account.entity";
import { Image } from "src/file-management/images/entities/image.entity";

@Entity()
export class User extends BaseEntity {
    @Column({ type: 'varchar', nullable: true })
    phone: string | null;

    @Column({ type: 'enum', enum: Gender, nullable: true })
    gender: Gender | null;

    @Column({ type: 'timestamp', nullable: true })
    dob: string | null;

    @OneToOne(() => Image, image => image.user_profileImage, { nullable: true })
    @JoinColumn()
    profileImage: Image | null;

    @OneToOne(() => Account, account => account.user, { nullable: true })
    account: Account | null;
}
