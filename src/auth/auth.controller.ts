import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  @Get('csrf')
  getCrsfToken(@Res({ passthrough: true }) res: FastifyReply) {
    return { csrfToken: res.generateCsrf() };
  }

  @Get('login')
  login(@Res() res: FastifyReply) {
    const params: URLSearchParams = new URLSearchParams();
    params.append('client_id', this.configService.get('KEYCLOAK_CLIENT_ID')!);
    params.append('response_type', 'code');
    params.append(
      'redirect_uri',
      `${this.configService.get('APP_URL')}/auth/callback`,
    );
    params.append('scope', 'openid profile email');

    const keycloakAuthUrl = `${this.configService.get('KEYCLOAK_URL')}/realms/${this.configService.get('KEYCLOAK_REALM')}/protocol/openid-connect/auth?${params.toString()}`;
    // Redirect 302 ไป Keycloak
    res.redirect(keycloakAuthUrl, HttpStatus.FOUND);
  }

  // 2. Keycloak ส่ง Code กลับมาที่นี่
  @Get('callback')
  async callback(@Query('code') code: string, @Res() res: FastifyReply) {
    if (!code) {
      return res.redirect(
        `${this.configService.get('FRONTEND_URL')}/login?error=no_code`,
        HttpStatus.FOUND,
      );
    }

    // แลก Token
    const tokens = await this.authService.getTokensFromKeycloak(code);
    // ฝัง Access Token ลง Cookie
    // หมายเหตุ: tokens.expires_in หน่วยเป็นวินาที แต่ maxAge ใน cookie options ของบาง version อาจต้องการ millisecond ให้เช็ค version fastify-cookie
    // ในที่นี้สมมติว่าเป็น millisecond ตามมาตรฐานทั่วไป (expires_in * 1000)

    res.setCookie('access_token', tokens.access_token, {
      httpOnly: true, // สำคัญที่สุด: JS อ่านไม่ได้
      secure: this.configService.get('NODE_ENV') === 'production', // ใช้ HTTPS ใน Prod
      sameSite: 'lax',
      path: '/',
      maxAge: tokens.expires_in,
    });

    // (Optional) เก็บ Refresh Token ถ้าต้องการ
    if (tokens.refresh_token) {
      res.setCookie('refresh_token', tokens.refresh_token, {
        httpOnly: true,
        secure: this.configService.get('NODE_ENV') === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: tokens.refresh_expires_in || 3600,
      });
    }

    // [Optional] เก็บ ID Token ไว้ใช้ตอน Logout เพื่อข้ามหน้ายืนยัน (ถ้าต้องการ)
    if (tokens.id_token) {
      res.setCookie('id_token', tokens.id_token, {
        httpOnly: true,
        secure: this.configService.get('NODE_ENV') === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: tokens.refresh_expires_in || 3600,
      });
    }
    // Redirect กลับไปหน้า Frontend
    res.redirect(
      this.configService.get('FRONTEND_URL') || '/',
      HttpStatus.FOUND,
    );
  }

  @Post('logout')
  logout(@Res() res: FastifyReply, @Req() req: any) {
    const params: URLSearchParams = new URLSearchParams();
    params.append(
      'client_id',
      this.configService.get('KEYCLOAK_CLIENT_ID') || '',
    );
    params.append(
      'post_logout_redirect_uri',
      this.configService.get('FRONTEND_URL') || '',
    );

    // [Tip] ถ้าอยากให้ Logout ทันทีโดยไม่ถามยืนยัน (Skip Confirmation)
    // ต้องส่ง id_token_hint ไปด้วย (ต้องเก็บ id_token ลง cookie ตอน callback ก่อน)
    if (req.cookies && req.cookies['id_token']) {
      params.append('id_token_hint', req.cookies['id_token']);
    }

    // Logout ที่ Keycloak ด้วย
    //const logoutUrl = `${this.configService.get('KEYCLOAK_URL')}/realms/${this.configService.get('KEYCLOAK_REALM')}/protocol/openid-connect/logout?redirect_uri=${this.configService.get('FRONTEND_URL')}`;
    const logoutUrl = `${this.configService.get('KEYCLOAK_URL')}/realms/${this.configService.get('KEYCLOAK_REALM')}/protocol/openid-connect/logout?${params.toString()}`;

    // 2. ลบ Cookie ฝั่งเราให้หมด (Clear Local Session)
    // สำคัญ: Options ต้องตรงกับตอน setCookie เป๊ะๆ (path, domain) ไม่งั้นลบไม่ออก
    const cookieOptions = {
      path: '/',
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax' as const,
    };

    res.clearCookie('access_token', cookieOptions);
    res.clearCookie('refresh_token', cookieOptions);
    res.clearCookie('id_token', cookieOptions); // ลบ id_token ด้วยถ้ามี

    res.send({ logoutUrl });
  }

  @UseGuards(AuthGuard('jwt')) // ใช้ Guard ที่เราทำไว้เช็ค Token
  @Get('profile')
  getProfile(@Req() req: any) {
    return req.user; // ส่งข้อมูล User กลับไปให้ Vue
  }

  @Post('refresh')
  async refresh(@Req() req: FastifyRequest, @Res() res: FastifyReply) {
    // 1. ดึง Refresh Token จาก Cookie
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token found');
    }

    // 2. เรียก Service ไปแลก Token ใหม่
    try {
      const tokens = await this.authService.refreshAccessToken(refreshToken);
      // 3. ตั้งค่า Cookie Options
      const cookieOptions = {
        httpOnly: true,
        secure: this.configService.get('NODE_ENV') === 'production',
        sameSite: 'lax' as const,
        path: '/',
      };
      // 4. Update Cookie: Access Token ใหม่
      res.setCookie('access_token', tokens.access_token, {
        httpOnly: true,
        secure: this.configService.get('NODE_ENV') === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: tokens.expires_in || 3600,
      });

      // 5. Update Cookie: Refresh Token ใหม่ (Token Rotation)
      if (tokens.refresh_token) {
        res.setCookie('refresh_token', tokens.refresh_token, {
          httpOnly: true,
          secure: this.configService.get('NODE_ENV') === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: tokens.refresh_expires_in || 3600,
        });
      }

      // Update ID Token ด้วยถ้ามี
      if (tokens.id_token) {
        res.setCookie('id_token', tokens.id_token, {
          httpOnly: true,
          secure: this.configService.get('NODE_ENV') === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: tokens.expires_in || 3600,
        });
      }
      res.send({ success: true });
    } catch (error) {
      // ถ้า Refresh ไม่ผ่าน (เช่น Token ขาด) ให้สั่งลบ Cookie เพื่อบังคับ Login ใหม่
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      res.clearCookie('id_token');
      throw new UnauthorizedException('Session expired');
    }
  }
}
