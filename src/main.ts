import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import fastifyCookie from '@fastify/cookie';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ logger: true }),
  );
  // Register Cookie Plugin
  await app.register(fastifyCookie, {
    secret: process.env.COOKIE_SECRET,
  });
  // Global Validation (สำคัญสำหรับ DTO)
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // ตัด field ขยะทิ้ง
      forbidNonWhitelisted: true, // แจ้ง Error ถ้าส่ง field ขยะมา
      transform: true, // แปลง Type อัตโนมัติ (เช่น string -> number ใน DTO)
    }),
  );

  //CORS setup
  app.enableCors({
    origin: 'http://localhost:3000', // URL ของ Frontend
    credentials: true, // อนุญาตให้รับ-ส่ง Cookie
  });
  await app.listen(process.env.PORT ?? 3000, '0.0.0.0');
  console.log(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();
