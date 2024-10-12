import { BeforeInsert, BeforeUpdate, Column, Entity, JoinColumn, OneToMany, OneToOne } from "typeorm";
import * as bcrypt from 'bcrypt';
import { BadRequestException } from "@nestjs/common";
import { BaseEntity } from "src/common/entities/base.entity";
import { AuthProvider, Role } from "src/common/types/global.type";
import { User } from "src/auth-system/users/entities/user.entity";
import { Image } from "src/file-management/images/entities/image.entity";
import { BCRYPT_HASH, EMAIL_REGEX, PASSWORD_SALT_COUNT } from "src/common/CONSTANTS";

@Entity()
export class Account extends BaseEntity {
    @Column({ type: 'varchar' })
    firstName!: string;

    @Column({ type: 'varchar', default: '' })
    lastName?: string;

    @Column({ type: 'varchar' })
    email!: string;

    @Column({ type: 'varchar', nullable: true })
    password?: string;

    @Column({ type: 'enum', enum: Role, default: Role.USER })
    role: Role;

    @Column({ type: 'boolean', default: false })
    isVerified: boolean = false;

    @Column({ type: 'enum', enum: AuthProvider, default: AuthProvider.CREDENTIALS })
    provider: AuthProvider;

    @Column({ type: 'simple-array' })
    prevPasswords: string[];

    @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
    passwordUpdatedAt: Date;

    @Column({ type: 'simple-array', nullable: true })
    refreshTokens: string[];

    @OneToOne(() => User, user => user.account, { onDelete: 'CASCADE', nullable: true })
    @JoinColumn()
    user: User;

    @OneToMany(() => Image, image => image.uploadedBy)
    images: Image[];

    @BeforeInsert()
    @BeforeUpdate()
    hashPassword() {
        if (!this.password) throw new BadRequestException('Password required');

        if (!BCRYPT_HASH.test(this.password)) this.password = bcrypt.hashSync(this.password, PASSWORD_SALT_COUNT);
    }

    @BeforeInsert()
    @BeforeUpdate()
    validateEmail() {
        if (!this.email) throw new BadRequestException('Email required');

        if (!EMAIL_REGEX.test(this.email)) throw new BadRequestException('Invalid email');
    }

}
