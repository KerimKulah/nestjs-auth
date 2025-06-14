import { forwardRef, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshTokenService } from './refresh-token.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../user/entities/user.entity';
import { Role } from '../role/entities/role.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { JwtGuard } from 'src/common/guards/JwtGuard';
import { RolesGuard } from 'src/common/guards/RolesGuard';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],  
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN') || '15m',
        },
      }),
    }),

    TypeOrmModule.forFeature([User, Role, RefreshToken]),
    forwardRef(() => UserModule)
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy, 
    JwtGuard,
    RolesGuard,
    RefreshTokenService
  ],
  exports: [
    JwtGuard,
    RolesGuard,
    AuthService, 
    JwtModule,
    JwtStrategy,
    RefreshTokenService
  ],
})

export class AuthModule {}