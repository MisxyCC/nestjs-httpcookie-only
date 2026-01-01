import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FastifyRequest } from 'fastify';

export interface JwtPayload {
  sub: number; //UserId ที่เรา map มาตอน sign
  username: string; //username
  iat: number; // (Optional) Issued At: เวลาที่สร้าง Token (JWT เติมให้อัตโนมัติ)
  exp?: number; // (Optional) Expiration Time: เวลาหมดอายุ (JWT เติมให้อัตโนมัติ)
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtStrategy.extractJWTFromCookie,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET')!,
    });
  }
  // Custom Extractor สำหรับ Fastify Cookie
  private static extractJWTFromCookie(req: FastifyRequest): string | null {
    // ตรวจสอบว่ามี Cookies และมี key 'access_token' หรือไม่
    if (req.cookies && 'access_token' in req.cookies) {
      return req.cookies['access_token'] || null;
    }
    return null;
  }

  async validate(payload: JwtPayload) {
    // payload คือข้อมูลที่แกะได้จาก Token (เช่น userId, username)
    // ตรงนี้สามารถเพิ่ม Logic เช็คกับ Database ได้ว่า User ยัง Active อยู่ไหม
    if (!payload) {
      throw new UnauthorizedException();
    }
    // ค่าที่ return ตรงนี้จะถูกแปะไปกับ req.user ใน Controller
    return { userId: payload.sub, username: payload.username };
  }
}
