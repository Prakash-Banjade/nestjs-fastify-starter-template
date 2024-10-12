import { Account } from "src/auth-system/accounts/entities/account.entity";
import { User } from "src/auth-system/users/entities/user.entity";
import { BaseEntity } from "src/common/entities/base.entity";
import { Column, Entity, ManyToOne, OneToOne } from "typeorm";

@Entity()
export class Image extends BaseEntity {
    @Column({ type: 'varchar' })
    url!: string

    @Column({ type: 'varchar' })
    mimeType!: string

    @Column({ type: 'varchar' })
    format!: string

    @Column({ type: 'varchar' })
    space!: string

    @Column({ type: 'real' })
    height!: number

    @Column({ type: 'real' })
    width!: number

    @Column({ type: 'int' })
    size!: number

    @Column({ type: 'varchar' })
    originalName!: string

    @Column({ type: 'varchar', default: '' })
    name!: string

    @ManyToOne(() => Account, account => account.images, { onDelete: 'CASCADE' })
    uploadedBy!: Account

    // relations
    @OneToOne(() => User, user => user.profileImage)
    user_profileImage: User;
}
