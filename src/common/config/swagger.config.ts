// swagger.config.ts
import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

export const SwaggerConfig = (app: INestApplication) => {
  const config = new DocumentBuilder()
    .setTitle('Auth Service API')
    .setDescription('Auth servisinin Swagger dökümantasyonu')
    .setVersion('1.0')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      'jwt' // security scheme name
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('swagger', app, document);
};
