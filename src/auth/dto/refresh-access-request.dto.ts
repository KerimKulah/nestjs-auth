import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional } from "class-validator";

export class RefreshAccessRequestDto {
    @ApiPropertyOptional()
    @IsOptional()
    public refreshTokenHash?: string;
}