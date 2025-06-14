import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from "class-validator";

export class ChangeEmailDto {
    @ApiProperty()
    @IsEmail()
    @IsNotEmpty({ message: 'Old email cannot be empty' })
    oldMail: string;

    @ApiProperty()
    @IsEmail()
    @IsNotEmpty({ message: 'New email cannot be empty' })
    newMail: string;
}