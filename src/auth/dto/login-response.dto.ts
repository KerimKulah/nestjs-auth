import { ApiProperty } from '@nestjs/swagger';

export class LoginResponseDto {
  @ApiProperty()
  accessToken: string;

  @ApiProperty({ type: String, format: 'date-time' })
  accessTokenExpiresAt: string;
}