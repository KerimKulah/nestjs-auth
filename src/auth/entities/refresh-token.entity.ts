import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn, UpdateDateColumn } from "typeorm";
import { User } from "../../user/entities/user.entity";

@Entity()
export class RefreshToken {
    @PrimaryGeneratedColumn()
    id: number;

    @Column(({ unique: true }))
    hash: string;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    @Column()
    expiresAt: Date;

    @Column({ nullable: true })
    deviceInfo: string;

    @Column({ nullable: true })
    ipAddress: string;

    @Column({ default: false })
    isRevoked: boolean;

    @Column({ nullable: true })
    usedAt: Date;

    @ManyToOne(() => User, (user) => user.refreshTokens, { onDelete: 'CASCADE' })
    user: User;
}
