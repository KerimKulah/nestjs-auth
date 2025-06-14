import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength, Matches, MaxLength } from "class-validator";


export class RegisterDto {
    @ApiProperty()
    @IsEmail()
    @IsNotEmpty({ message: 'Email cannot be empty' })
    email: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty({ message: 'Password cannot be empty' })
    @MinLength(6, { message: 'Password must be at least 6 characters' })
    @MaxLength(20, { message: 'Password cannot exceed 20 characters' })
    @Matches(/^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]*$/, { message: 'Password must contain at least one letter and one number' })
    password: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty({ message: 'Confirm password cannot be empty' })
    confirmPassword: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty({ message: 'First name cannot be empty' })
    firstName: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty({ message: 'Last name cannot be empty' })
    lastName: string;
}
