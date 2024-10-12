import { BeforeInsert, BeforeUpdate, Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import * as bcrypt from 'bcrypt'
import { PASSWORD_SALT_COUNT } from "src/common/CONSTANTS";

@Entity()
export class EmailVerificationPending {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column('varchar')
    email: string;

    @Column('varchar')
    hashedVerificationToken: string;

    @Column('varchar')
    otp: string;

    @Column('timestamp')
    createdAt: Date;

    @BeforeInsert()
    @BeforeUpdate()
    setCreatedAt() {
        this.createdAt = new Date();
    }

    @BeforeInsert()
    @BeforeUpdate()
    hashOtp() {
        this.otp = bcrypt.hashSync(this.otp, PASSWORD_SALT_COUNT);
    }
}