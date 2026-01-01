import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import fastifyCookie from '@fastify/cookie';
import { ValidationPipe } from '@nestjs/common';
import { fastifyCsrfProtection } from '@fastify/csrf-protection';
import { FastifyRequest, FastifyReply } from 'fastify';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ logger: true }),
  );

  // 1. ดึง Fastify Instance ออกมาก่อน
  const fastify = app.getHttpAdapter().getInstance();

  // 1. Register Cookie (ต้องมาก่อน CSRF)
  await app.register(fastifyCookie, {
    secret: process.env.COOKIE_SECRET,
  });

  // 2. Register CSRF
  await app.register(fastifyCsrfProtection, {
    cookieOpts: {
      signed: true,
      httpOnly: true,
      sameSite: 'lax',
    },
  });

  // 3. Setup Hook (Global Protection)
  // ดึง instance ของ fastify ออกมาเพื่อ addHook

  fastify.addHook(
    'onRequest',
    async (req: FastifyRequest, res: FastifyReply) => {
      // ข้ามการตรวจ GET, HEAD, OPTIONS
      if (
        req.method !== 'GET' &&
        req.method !== 'HEAD' &&
        req.method !== 'OPTIONS'
      ) {
        fastify.csrfProtection(req, res, () => {});
      }
    },
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // ตัด field ขยะทิ้ง
      forbidNonWhitelisted: true, // แจ้ง Error ถ้าส่ง field ขยะมา
      transform: true, // แปลง Type อัตโนมัติ (เช่น string -> number ใน DTO)
    }),
  );

  app.enableCors({
    origin: 'http://localhost:5173', // URL ของ Frontend
    credentials: true, // อนุญาตให้รับ-ส่ง Cookie
  });

  await app.listen(process.env.PORT ?? 3000, '0.0.0.0');
  console.log(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();
