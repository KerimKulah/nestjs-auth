import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength, MaxLength, Matches, IsNotEmpty } from 'class-validator';

export class ChangePasswordDto {
    @ApiProperty()
    @IsString()
    @IsNotEmpty({ message: 'Old password cannot be empty' })
    oldPassword: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty({ message: 'Password cannot be empty' })
    @MinLength(6, { message: 'Password must be at least 6 characters' })
    @MaxLength(20, { message: 'Password cannot exceed 20 characters' })
    @Matches(/^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]*$/, { message: 'Password must contain at least one letter and one number' })
    newPassword: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty({ message: 'Confirm password cannot be empty' })
    confirmPassword: string;
}