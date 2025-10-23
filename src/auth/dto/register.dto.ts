import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  IsDateString,
} from 'class-validator';

export class RegisterDto {
  @IsNotEmpty({
    message: 'Name is required',
  })
  @IsString()
  name: string;

  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail()
  email: string;

  @IsNotEmpty({ message: 'Password is required' })
  @IsString()
  @MinLength(6, { message: 'Password must be at least 6 characters' })
  password: string;

  @IsNotEmpty({ message: 'Birth date is required' })
  @IsDateString()
  birthDate: string;
}
