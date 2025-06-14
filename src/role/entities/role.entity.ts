import { User } from "src/user/entities/user.entity";
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from "typeorm";

@Entity()
export class Role {
    @PrimaryGeneratedColumn()
    id: number;

    @Column(({ unique: true }))
    name: string; // eg. "EMPLOYEE", "ADMIN"

    @ManyToMany(() => User, (user) => user.roles)
    users: User[];
}
