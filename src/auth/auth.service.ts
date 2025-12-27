import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    // private usersService: UsersService // Inject User Service ของจริงตรงนี้
  ) {}

  async login(loginDto: LoginDto) {
    // 1. ตรวจสอบ Username/Password (Mock)
    // ใน Code จริงต้องใช้ bcrypt.compare(loginDto.password, user.password)
    if (
      loginDto.username !== 'admin' ||
      loginDto.password !== 'password123456'
    ) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const user = { userId: 1, username: 'admin' };

    // 2. สร้าง Payload
    const payload = { username: user.username, sub: user.userId };

    // 3. Sign Token
    return {
      accessToken: this.jwtService.sign(payload),
    };
  }
}
