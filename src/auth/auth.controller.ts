import { Controller, Post, Body, Req, Get, UseGuards, HttpStatus, HttpCode, Param, Put, Res, ParseIntPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request } from 'express';
import { CurrentUser } from 'src/common/decorators/currentuser.decorator';
import { User } from 'src/user/entities/user.entity';
import { JwtGuard } from '../common/guards/JwtGuard';
import { LoginDto } from './dto/login-dto';
import { RefreshAccessRequestDto } from './dto/refresh-access-request.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { RefreshAccessDto } from './dto/refresh-access.dto';
import { RegisterDto } from './dto/register-dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ChangeEmailDto } from './dto/change-email.dto';
import { Response } from 'express';
import { UnauthorizedException } from '@nestjs/common';
import { Roles } from 'src/common/decorators/roles.decorator';
import { ApiBearerAuth } from '@nestjs/swagger';
import { RolesGuard } from 'src/common/guards/RolesGuard';
import { UserService } from 'src/user/user.service';

@Controller('auth')
@ApiBearerAuth('jwt')
export class AuthController {
  constructor(private readonly authService: AuthService, private readonly userService: UserService) { }

  @Post('login')
  async login(@Req() req: Request, @Res({ passthrough: true }) res: Response, @Body() loginDto: LoginDto): Promise<LoginResponseDto> {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.ip || 'unknown';
    const device = req.get('user-agent') || 'unknown';

    const loginServiceResponse = await this.authService.login(loginDto, ip, device);
    const refreshToken = loginServiceResponse.refreshToken

    // Refresh token cookie olarak kaydet
    res.cookie('refreshToken', refreshToken.hash, {
      httpOnly: true,
      secure: false, //TODO: true
      sameSite: 'strict',
      path: '/',
      maxAge: refreshToken.expiresAt.getTime() - Date.now(),
    });

    return loginServiceResponse.loginResponseDto;
  }


  @Post('register')
  @HttpCode(201)
  async register(@Body() registerDto: RegisterDto): Promise<{ message: string }> {
    return this.authService.register(registerDto);
  }

  @UseGuards(JwtGuard)
  @Get('current-user')
   async getCurrentUser(@CurrentUser() userPayload): Promise<User> {
   const user = await this.userService.findOne(userPayload.id);
   return user;
  }

  //RefreshAccess
  @Post('refresh-access')
  async refreshAccess(@Body() refreshDto: RefreshAccessRequestDto, @Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<RefreshAccessDto> {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.ip || 'unknown';
    const device = req.get('user-agent') || 'unknown';

    const currentRefreshToken = refreshDto.refreshTokenHash || req.cookies['refreshToken'];
    if (!currentRefreshToken) throw new UnauthorizedException('Refresh token not found');

    const refreshResponse = await this.authService.refreshAccess(currentRefreshToken, ip, device);
    const newRefreshToken = refreshResponse.refreshToken

    // Yeni Refresh token cookie olarak kaydet
    res.cookie('refreshToken', newRefreshToken.hash, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: newRefreshToken.expiresAt.getTime() - Date.now(),
    });

    // Yeni Access token
    return refreshResponse.refreshAccessDto;
  }

  //Logout Current Device
  @Post('logout')
  @UseGuards(JwtGuard)
  async logout(@CurrentUser() userPayload, @Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<{ message: string }> {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : req.ip || 'unknown';
    const device = req.get('user-agent') || 'unknown';

    const user = await this.userService.findOne(userPayload.id);

    const response = await this.authService.logoutCurrentDevice(user, device, ip);

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });

    return response;
  }

  //Logout All Devices
  @Post('logout-all')
  @UseGuards(JwtGuard)
  async logoutAllDevices(@CurrentUser() userPayload, @Res({ passthrough: true }) res: Response): Promise<{ message: string }> {

    const user = await this.userService.findOne(userPayload.id);

    const response = await this.authService.logoutAllDevices(user);

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });

    return response;
  }

  //Force Logout 
  @Post('force-logout/:userId')
  @UseGuards(JwtGuard, RolesGuard)
  @Roles('admin')
  async forceLogout(@Param('userId', ParseIntPipe) userId: number): Promise<{ message: string }> {
    return this.authService.forceLogout(userId);
  }

  //ChangePassword
  @Put('change-password')
  @UseGuards(JwtGuard)
  async changePassword(@CurrentUser() userPayload, @Body() changePasswordDto: ChangePasswordDto): Promise<{ message: string }> {
    const user = await this.userService.findOne(userPayload.id);
    return this.authService.changePassword(user, changePasswordDto);
  }

  //ChangeEmail
  @Put('change-email')
  @UseGuards(JwtGuard)
  async changeEmail(@CurrentUser() userPayload, @Body() changeEmailDto: ChangeEmailDto): Promise<{ message: string }> {
    const user = await this.userService.findOne(userPayload.id);
    return this.authService.changeEmail(user, changeEmailDto);
  }

  // DENEME
  @Get('deneme')
  @UseGuards(JwtGuard, RolesGuard)
  @Roles('admin')
  async deneme(): Promise<{ message: string }> {
    return { message: 'Deneme' };
  }

  // ---- BUNLAR ICIN MAIL SERVISI GEREKLI ----
  //ForgotPassword
  //ResetPassword 
}
