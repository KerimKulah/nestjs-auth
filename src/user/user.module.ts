import { forwardRef, Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { AuthModule } from 'src/auth/auth.module';
import { RoleModule } from 'src/role/role.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    forwardRef(() => AuthModule),  
    RoleModule,
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService, TypeOrmModule]
})
export class UserModule { }
