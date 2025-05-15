import { BeforeInsert, BeforeUpdate, Column, Entity, Index, JoinColumn, OneToMany, OneToOne } from "typeorm";
import * as bcrypt from 'bcrypt';
import { BadRequestException } from "@nestjs/common";
import { BaseEntity } from "src/common/entities/base.entity";
import { Role } from "src/common/types/global.type";
import { User } from "src/auth-system/users/entities/user.entity";
import { Image } from "src/file-management/images/entities/image.entity";
import { BCRYPT_HASH, EMAIL_REGEX, PASSWORD_SALT_COUNT } from "src/common/CONSTANTS";
import { LoginDevice } from "./login-device.entity";
import { WebAuthnCredential } from "src/auth-system/webAuthn/entities/webAuthnCredential.entity";
import { getLowerCasedFullName } from "src/common/utils";

@Entity()
export class Account extends BaseEntity {
    @Column({ type: 'varchar' })
    firstName!: string;

    @Column({ type: 'varchar', default: '' })
    lastName?: string;

    @Index()
    @Column({ type: 'varchar' })
    lowerCaseFullName: string;

    setLowerCasedFullName() {
        this.lowerCaseFullName = getLowerCasedFullName(this.firstName, this.lastName);
    }

    @Index({ unique: true })
    @Column({ type: 'varchar' })
    email!: string;

    @Column({ type: 'varchar', nullable: true })
    password?: string;

    @Column({ type: 'string', enum: Role, default: Role.USER })
    role: Role;

    @Column({ type: 'timestamp', nullable: true })
    verifiedAt: Date | null = null;

    @Column({ type: 'simple-array' })
    prevPasswords: string[];

    @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
    passwordUpdatedAt: Date;

    @OneToMany(() => LoginDevice, loginDevice => loginDevice.account)
    loginDevices: LoginDevice[];

    @Column({ type: 'timestamp', nullable: true })
    twoFaEnabledAt: Date | null;

    @OneToMany(() => WebAuthnCredential, passkey => passkey.account)
    webAuthnCredentials: WebAuthnCredential[];

    @OneToOne(() => Image, image => image.account_profileImage, { nullable: true })
    @JoinColumn()
    profileImage: Image | null;

    @OneToOne(() => User, user => user.account, { cascade: true, nullable: true })
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
