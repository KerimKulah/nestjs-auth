import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { RoleModule } from './role/role.module';
import { SeedService } from './seed/seed.service';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { TypeOrmModule } from '@nestjs/typeorm';
import { addTransactionalDataSource, initializeTransactionalContext } from 'typeorm-transactional';
import { DataSource } from 'typeorm';

@Module({
  imports: [
    
    // Modules
    AuthModule,
    UserModule,
    RoleModule,

    // Configs etc.
    ConfigModule.forRoot({ isGlobal: true }),
    ScheduleModule.forRoot(),

    // TypeORM
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT ?? '5432', 10),
      username: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      autoLoadEntities: true,
      synchronize: true,
      logging: true,
    }),

  ],
  providers: [SeedService],
})

export class AppModule {
  constructor(private readonly dataSource: DataSource) {
    addTransactionalDataSource(this.dataSource);
    initializeTransactionalContext();
  }
}
