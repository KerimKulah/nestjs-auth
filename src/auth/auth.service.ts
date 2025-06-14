import { BadRequestException, HttpException, Injectable, InternalServerErrorException, Logger, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../user/entities/user.entity';
import { RefreshTokenService } from './refresh-token.service';
import { Repository } from 'typeorm';
import { LoginResponseDto } from './dto/login-response.dto';
import { RefreshAccessDto } from './dto/refresh-access.dto';
import { LoginDto } from './dto/login-dto';
import { RegisterDto } from './dto/register-dto';
import { Role } from 'src/role/entities/role.entity';
import { CurrentUser } from 'src/common/decorators/currentuser.decorator';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ChangeEmailDto } from './dto/change-email.dto';
import { RefreshToken } from './entities/refresh-token.entity';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly jwtService: JwtService,
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    @InjectRepository(Role) private readonly roleRepository: Repository<Role>,
    @InjectRepository(RefreshToken) private readonly refreshTokenRepository: Repository<RefreshToken>,
    private readonly refreshTokenService: RefreshTokenService,
  ) { }

  //LOGIN 
  async login(loginDto: LoginDto, ip: string, device: string): Promise<{ loginResponseDto: LoginResponseDto; refreshToken: RefreshToken }> {
    try {
      this.logger.log(`Login attempt for email: ${loginDto.email}, IP: ${ip}, Device: ${device}`);

      // Mail kontrolü
      const user = await this.userRepository.findOne({where: { email: loginDto.email }, relations: ['roles']}); 
      if (!user) {
        this.logger.warn(`Login failed - User not found for email: ${loginDto.email}`);
        throw new UnauthorizedException('Invalid credentials');
      }

      // Şifre kontrolü
      const passwordMatches = await bcrypt.compare(loginDto.password, user.password);
      if (!passwordMatches) {
        this.logger.warn(`Login failed - Invalid password for user: ${user.id}`);
        throw new UnauthorizedException('Invalid credentials');
      }

      // Access Token olusturma
      const accessToken = this.jwtService.sign(
        { sub: user.id, email: user.email, roles: user.roles.map(role => role.name) },
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );

      // Refresh Token olusturma, db kaydetme (httponlycookie kaydetme controllerda yapılmalı.)
      const refreshToken = await this.refreshTokenService.createRefreshTokenAndSave(user, ip, device);

      // Oluşturulan access token expiration süresini al
      const decoded = this.jwtService.decode(accessToken) as { exp?: number } | null;
      if (!decoded || typeof decoded.exp !== 'number') {
        this.logger.error(`Invalid token expiration for user: ${user.id}`);
        throw new Error('Invalid token expiration');
      }

      // LoginResponseDto oluştur ve return et
      const loginResponseDto = new LoginResponseDto();
      loginResponseDto.accessToken = accessToken;
      loginResponseDto.accessTokenExpiresAt = new Date(decoded.exp * 1000).toLocaleString("tr-TR", {
        timeZone: "Europe/Istanbul"
      });
      this.logger.log(`Login successful for user: ${user.id}, email: ${user.email}`);
      return { loginResponseDto, refreshToken };

    } catch (error) {
      this.logger.error(`Login error for email: ${loginDto.email}, IP: ${ip}`, error.stack);
      throw error instanceof HttpException ? error : new InternalServerErrorException('Login failed');
    }
  }

  // REFRESH ACCESS TOKEN (WITH REFRESH TOKEN) ??
  async refreshAccess(hash: string, ip: string, device: string): Promise<{ refreshAccessDto: RefreshAccessDto, refreshToken: RefreshToken }> {
    try {
      this.logger.log(`Refresh token attempt, IP: ${ip}, Device: ${device}`);

      // Refresh token dogrulama
      const refreshToken = await this.refreshTokenService.validateRefreshToken(hash);

      if (!refreshToken) {
        this.logger.warn(`Invalid refresh token used, IP: ${ip}, Device: ${device}`);
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Refresh Tokenden Kullanıcı bilgilerini al
      const user = refreshToken.user;

      // Mevcut Refresh token revoke et ve kullanıldı olarak işaretle
      await this.refreshTokenRepository.update({ hash }, { isRevoked: true, usedAt: new Date() });

      // Access token oluştur
      const accessToken = this.jwtService.sign(
        { sub: user.id, email: user.email, roles: user.roles.map(role => role.name) },
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );

      // Yeni refresh token oluştur ve kaydet
      const newRefreshToken = await this.refreshTokenService.createRefreshTokenAndSave(user, ip, device);

      // Access token expiration süresini al
      const decoded = this.jwtService.decode(accessToken) as { exp?: number } | null;
      if (!decoded || typeof decoded.exp !== 'number') {
        this.logger.error(`Invalid token expiration during refresh for user: ${user.id}`);
        throw new Error('Invalid token expiration');
      }

      const refreshAccessDto = new RefreshAccessDto();
      refreshAccessDto.accessToken = accessToken;
      refreshAccessDto.accessTokenExpiresAt = new Date(decoded.exp * 1000).toLocaleString("tr-TR", {
        timeZone: "Europe/Istanbul" 
      });

      this.logger.log(`Token refresh successful for user: ${user.id}`);
      return { refreshAccessDto, refreshToken: newRefreshToken };

    } catch (error) {
      this.logger.error(`Token refresh error, IP: ${ip}, Device: ${device}`, error.stack);
      throw error instanceof HttpException ? error : new InternalServerErrorException('Token refresh failed');
    }
  }

  // REGISTER (İçe kapalı sistemler kullanılmaz)
  async register(registerDto: RegisterDto): Promise<{ message: string }> {
    try {
      let { firstName, lastName, email, password, confirmPassword } = registerDto;
      email = email.toLowerCase();

      this.logger.log(`Registration attempt for email: ${email}`);

      // Mail önceden kayıtlı mı?
      const existingUser = await this.userRepository.findOne({ where: { email } });
      if (existingUser) {
        this.logger.warn(`Registration failed - Email already exists: ${email}`);
        throw new BadRequestException('Email already exists');
      }

      // Password eşleşiyor mu?
      if (password !== confirmPassword) {
        this.logger.warn(`Registration failed - Passwords do not match for email: ${email}`);
        throw new BadRequestException('Passwords do not match');
      }

      const role = await this.roleRepository.findOne({ where: { name: 'employee' } });
      if (!role) {
        this.logger.error(`Registration failed - Role "employee" not found`);
        throw new NotFoundException('Role "employee" not found');
      }

      const user = this.userRepository.create({
        firstName,
        lastName,
        email,
        password: await bcrypt.hash(password, 10),
        roles: [role],
      });

      await this.userRepository.save(user);

      this.logger.log(`User registered successfully: ${email}, ID: ${user.id}`);
      return { message: 'User registered successfully' };

    } catch (error) {
      this.logger.error(`Registration error for email: ${registerDto.email}`, error.stack);
      throw error instanceof HttpException ? error : new InternalServerErrorException('Registration failed');
    }
  }

  // CHANGE PASSWORD (OTURUMDAKI KULLANICI)
  async changePassword(user: User, changePasswordDto: ChangePasswordDto): Promise<{ message: string }> {
    try {
      const { oldPassword, newPassword, confirmPassword } = changePasswordDto;

      this.logger.log(`Password change attempt for user ID: ${user.id}`);

      // Yeni şifre ile tekrar şifresi uyuşuyor mu?
      if (newPassword !== confirmPassword) {
        this.logger.warn(`Password change failed - New passwords do not match for user ID: ${user.id}`);
        throw new BadRequestException('New passwords do not match');
      }

      // Kullanıcıyı veritabanından tekrar çekmek daha güvenlidir (şifre hash'inin güncel olduğunu garanti eder)
      const existingUser = await this.userRepository.findOne({ where: { id: user.id } });
      if (!existingUser) {
        this.logger.error(`Password change failed - User not found for ID: ${user.id}`);
        throw new NotFoundException('User not found');
      }

      // Eski şifre doğru mu?
      const passwordMatches = await bcrypt.compare(oldPassword, existingUser.password);
      if (!passwordMatches) {
        this.logger.warn(`Password change failed - Old password is incorrect for user ID: ${user.id}`);
        throw new UnauthorizedException('Old password is incorrect');
      }

      // Yeni şifre hash'lenip kaydediliyor
      existingUser.password = await bcrypt.hash(newPassword, 10);
      await this.userRepository.save(existingUser);

      this.logger.log(`Password changed successfully for user ID: ${user.id}`);
      return { message: 'Password changed successfully' };

    } catch (error) {
      this.logger.error(`Password change error for user ID: ${user.id}`, error.stack);
      throw error instanceof HttpException ? error : new InternalServerErrorException('Password change failed');
    }
  }

  // CHANGE EMAIL(OTURUMDAKI KULLANICI)
  async changeEmail(user: User, changeEmailDto: ChangeEmailDto): Promise<{ message: string }> {
    try {
      let { oldMail, newMail } = changeEmailDto;
      oldMail = oldMail.toLowerCase();
      newMail = newMail.toLowerCase();

      this.logger.log(`Email change attempt for user ID: ${user.id}, from: ${oldMail} to: ${newMail}`);

      // Kontroller
      if (oldMail !== user.email) {
        this.logger.warn(`Email change failed - Old email is incorrect for user ID: ${user.id}`);
        throw new BadRequestException('Old email is incorrect');
      }

      if (oldMail === newMail) {
        this.logger.warn(`Email change failed - New email cannot be same as old email for user ID: ${user.id}`);
        throw new BadRequestException('New email cannot be same as old email');
      }

      // New mail zaten kullanılıyor mu?
      const existingUser = await this.userRepository.findOne({ where: { email: newMail } });
      if (existingUser) {
        this.logger.warn(`Email change failed - Email already exists: ${newMail} for user ID: ${user.id}`);
        throw new BadRequestException('Email already exists');
      }

      user.email = newMail.toLowerCase();
      await this.userRepository.save(user);

      this.logger.log(`Email changed successfully for user ID: ${user.id}, new email: ${newMail}`);
      return { message: 'Email changed successfully' };

    } catch (error) {
      this.logger.error(`Email change error for user ID: ${user.id}`, error.stack);
      throw error instanceof HttpException ? error : new InternalServerErrorException('Email change failed');
    }
  }

  // LOGOUT CURRENT DEVICE 
  async logoutCurrentDevice(user: User, device: string, ip: string): Promise<{ message: string }> {
    try {
      this.logger.log(`Current device logout for user ID: ${user.id}, Device: ${device}, IP: ${ip}`);

      const currentRefreshToken = await this.refreshTokenService.getCurrentRefreshToken(user, device, ip);
      const result = await this.refreshTokenService.revokeTokenByHash(currentRefreshToken.hash);

      this.logger.log(`Current device logout successful for user ID: ${user.id}`);
      return result;

    } catch (error) {
      this.logger.error(`Current device logout error for user ID: ${user.id}, Device: ${device}, IP: ${ip}`, error.stack);
      throw new InternalServerErrorException('Logout failed');
    }
  }

  // LOGOUT ALL DEVICES
  async logoutAllDevices(user: User): Promise<{ message: string }> {
    try {
      this.logger.log(`Logout all devices for user ID: ${user.id}`);
      const result = await this.refreshTokenService.revokeAllTokensByUser(user);
      this.logger.log(`Logout all devices successful for user ID: ${user.id}`);
      return result;
    } catch (error) {
      this.logger.error(`Logout all devices error for user ID: ${user.id}`, error.stack);
      throw new InternalServerErrorException('Error revoking refresh tokens');
    }
  }

  // FORCE LOGOUT (Çalınmalara karşı)
  async forceLogout(userId: number): Promise<{ message: string }> {
    try {
      this.logger.log(`Force logout attempt for user ID: ${userId}`);

      const user = await this.userRepository.findOne({ where: { id: userId } });
      if (!user) {
        this.logger.warn(`Force logout failed - User not found for ID: ${userId}`);
        throw new NotFoundException('User not found');
      }

      const result = await this.refreshTokenService.revokeAllTokensByUser(user);

      this.logger.log(`Force logout successful for user ID: ${userId}`);
      return result;

    } catch (error) {
      this.logger.error(`Force logout error for user ID: ${userId}`, error.stack);
      throw error instanceof HttpException ? error : new InternalServerErrorException('Force logout failed');
    }
  }

}