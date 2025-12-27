import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import type { FastifyReply } from 'fastify';
import { AuthService } from './auth.service';
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) response: FastifyReply,
  ) {
    // 1. เรียก Service เพื่อตรวจสอบ user และสร้าง token
    const { accessToken } = await this.authService.login(loginDto);

    // 2. คำนวณ maxAge เป็น "วินาที" (Fastify Cookie ใช้หน่วยวินาที)
    // 1 วัน = 24 ชม * 60 นาที * 60 วินาที = 86400
    const oneDayInSeconds: number = 24 * 60 * 60;

    // 3. Set Cookie
    response.setCookie('access_token', accessToken, {
      httpOnly: true, //ป้องกัน XSS: JS อ่านไม่ได้
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // ป้องกัน CSRF
      path: '/', // ให้ Cookie นี้ใช้ได้กับทุก route
      maxAge: oneDayInSeconds, // อายุ Cookie
      // signed: true // ถ้าเปิดตรงนี้ ใน Strategy ต้องใช้ unsignCookie (แนะนำปิดไว้ก่อนเพื่อความง่าย)
    });

    return {
      message: 'Login successfully',
      user: { username: loginDto.username },
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Res({ passthrough: true }) response: FastifyReply) {
    // ล้าง Cookie (ต้องระบุ path ให้ตรงกับตอนสร้าง
    response.clearCookie('access_token', { path: '/' });
    return { message: 'Logout successful' };
  }
}
