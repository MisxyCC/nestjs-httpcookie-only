import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FastifyRequest } from 'fastify';
import passport from 'passport';
import { passportJwtSecret } from 'jwks-rsa';

export interface JwtPayload {
  sub: number; //UserId ที่เรา map มาตอน sign
  username: string; //username
  iat: number; // (Optional) Issued At: เวลาที่สร้าง Token (JWT เติมให้อัตโนมัติ)
  exp?: number; // (Optional) Expiration Time: เวลาหมดอายุ (JWT เติมให้อัตโนมัติ)
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    const keycloakUrl: string = configService.get<string>('KEYCLOAK_URL') || '';
    const realm: string = configService.get<string>('KEYCLOAK_REALM') || '';

    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtStrategy.extractJWTFromCookie,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKeyProvider: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `${keycloakUrl}/realms/${realm}/protocol/openid-connect/certs`,
      }),
      algorithms: ['RS256'],
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

  async validate(payload: any) {
    // payload คือข้อมูลที่แกะได้จาก Token (เช่น userId, username)
    // ตรงนี้สามารถเพิ่ม Logic เช็คกับ Database ได้ว่า User ยัง Active อยู่ไหม
    if (!payload) {
      throw new UnauthorizedException();
    }
    // ค่าที่ return ตรงนี้จะถูกแปะไปกับ req.user ใน Controller
    return {
      userId: payload.sub,
      username: payload.preferred_username,
      email: payload.email,
      roles: payload.realm_access?.roles || [],
    };
  }
}
