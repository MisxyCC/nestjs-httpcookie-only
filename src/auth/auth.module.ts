import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './jwt.strategy';
// import { UsersModule } from '../users/users.module'; // อย่าลืม Import module user ของคุณ

@Module({
  imports: [
    // UsersModule, // Uncomment เมื่อมี UserModule จริง
    PassportModule,
    ConfigModule, // จำเป็นสำหรับการอ่าน .env
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          // อ่านค่าเวลาหมดอายุจาก env หรือ default 1 วัน
          expiresIn: configService.get<string>('JWT_EXPIRATION') ?? '1d',
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
