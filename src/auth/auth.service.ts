import {
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import * as qs from 'qs';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}

  async getTokensFromKeycloak(code: string) {
    // 1. Get variable values
    const baseUrl = this.configService.get<string>('KEYCLOAK_URL');
    const realm = this.configService.get<string>('KEYCLOAK_REALM');

    // 2. Debug Log: Print to see if values are missing?
    this.logger.log(`Connecting to Keycloak: URL=${baseUrl}, Realm=${realm}`);

    if (!baseUrl || !realm) {
      throw new InternalServerErrorException('Keycloak Configuration Missing');
    }

    // 3. Construct URL
    const url = `${baseUrl}/realms/${realm}/protocol/openid-connect/token`;

    const payload = {
      grant_type: 'authorization_code',
      client_id: this.configService.get('KEYCLOAK_CLIENT_ID'),
      client_secret: this.configService.get('KEYCLOAK_CLIENT_SECRET'),
      code: code,
      redirect_uri: `${this.configService.get('APP_URL')}/auth/callback`,
    };

    try {
      const { data } = await firstValueFrom(
        this.httpService.post(url, qs.stringify(payload), {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }),
      );
      return data;
    } catch (error) {
      // Print detailed error
      this.logger.error(`Error exchanging token: ${error.message}`);
      if (error.response) {
        this.logger.error(JSON.stringify(error.response.data));
      }
      throw error;
    }
  }
}
