import { Role } from "src/role/entities/role.entity";
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany, JoinTable, OneToMany, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from "typeorm";
import { RefreshToken } from "src/auth/entities/refresh-token.entity";

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    firstName: string;

    @Column()
    lastName: string;

    @Column()
    password: string;

    @Column({ unique: true })
    email: string;

    @ManyToMany(() => Role, (role) => role.users)
    @JoinTable()
    roles: Role[];

    @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
    refreshTokens: RefreshToken[];

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    @Column({ default: true })
    isActive: boolean;

    @DeleteDateColumn()
    deletedAt: Date;
}

