import { AuthenticatorTransportFuture, CredentialDeviceType } from "@simplewebauthn/server";
import { Account } from "src/auth-system/accounts/entities/account.entity";
import { BaseEntity } from "src/common/entities/base.entity";
import { Column, Entity, ManyToOne } from "typeorm";

@Entity()
export class WebAuthnCredential extends BaseEntity {
    @ManyToOne(() => Account, account => account.webAuthnCredentials, { onDelete: 'CASCADE' })
    account: Account

    @Column({ type: "varchar" })
    name: string;

    @Column()
    credentialId: string;

    @Column({ type: 'blob' })
    publicKey: Buffer;

    @Column({ type: 'varchar' })
    deviceType: CredentialDeviceType;

    @Column({ type: 'boolean', default: false })
    backedUp: boolean;

    @Column({ type: 'int', default: 0 })
    counter: number;

    @Column({ type: 'simple-array' })
    transports?: AuthenticatorTransportFuture[];

    @Column({ type: 'timestamp', nullable: true })
    lastUsed: Date;
}