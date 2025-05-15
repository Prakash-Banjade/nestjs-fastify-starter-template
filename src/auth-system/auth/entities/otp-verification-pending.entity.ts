import { BeforeInsert, BeforeUpdate, Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import * as bcrypt from 'bcrypt';
import { PASSWORD_SALT_COUNT } from "src/common/CONSTANTS";

export enum EOptVerificationType {
    EMAIL_VERIFICATION = 'email-verification',
    TWOFACTOR_VERIFICATION = 'twofactor-verification'
}

@Entity()
export class OtpVerificationPending {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column('varchar')
    email: string;

    @Column('varchar')
    hashedVerificationToken: string;

    @Column({ type: 'string', enum: EOptVerificationType })
    type: EOptVerificationType;

    @Column('varchar')
    otp: string;

    @Column('timestamp')
    createdAt: Date;

    @Column({ type: 'text', nullable: true })
    deviceId: string;

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