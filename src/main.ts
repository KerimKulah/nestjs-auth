
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';
import * as compression from 'compression';
import * as cookieParser from 'cookie-parser';
import { SwaggerConfig } from './common/config/swagger.config';
import { SeedService } from './seed/seed.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix('api');

  app.use(cookieParser());

  app.use(helmet());

  app.use(compression());

  // Swagger config
  SwaggerConfig(app);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  app.enableCors({
    origin: ['http://localhost:3000', 'http://localhost:' + (process.env.PORT || '3000')],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
    credentials: true,
  });

  // Seed işlemini uygulama başlatıldıktan sonra çağır
  try {
    const seedService = app.get(SeedService);
    await seedService.seedAll();
    console.log('🟢 Seed işlemi başarıyla tamamlandı.');
  } catch (err) {
    console.error('Seed işlemi sırasında hata:', err);
  }

  await app.listen(process.env.PORT || 3000, '0.0.0.0');

  console.log(`🚀 Application is running on: ${await app.getUrl()}`);

}

bootstrap();
