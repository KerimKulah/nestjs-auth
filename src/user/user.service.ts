import { Injectable, BadRequestException, NotFoundException, ConflictException, Logger, InternalServerErrorException, HttpException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { In, Repository } from 'typeorm';
import { Role } from 'src/role/entities/role.entity';
import * as bcrypt from 'bcrypt';
import { UpdateUserDto } from './dto/update-user.dto';
import { Transactional } from 'typeorm-transactional';
import { UpdateUserRoleDto } from './dto/update-user-role.dto';

@Injectable()
export class UserService {

  private readonly logger = new Logger(UserService.name);

  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    @InjectRepository(Role) private readonly roleRepository: Repository<Role>
  ) { }

  // CREATE USER
  @Transactional()
  async create(createUserDto: CreateUserDto): Promise<{ message: string }> {
    let { firstName, lastName, email, password, confirmPassword } = createUserDto;
    email = email.toLowerCase();

    // Sadece kritik işlemler için log
    this.logger.debug(`User creation requested for: ${this.maskEmail(email)}`);

    try {
      // Check existing user
      const existingUser = await this.userRepository.findOne({ where: { email } });
      if (existingUser) {
        this.logger.warn(`User creation failed - email already exists: ${this.maskEmail(email)}`);
        throw new BadRequestException('Email already exists');
      }

      // Validate password match
      if (password !== confirmPassword) {
        this.logger.warn(`User creation failed - password mismatch for: ${this.maskEmail(email)}`);
        throw new BadRequestException('Passwords do not match');
      }

      // Get employee role
      const role = await this.roleRepository.findOne({ where: { name: 'employee' } });
      if (!role) {
        this.logger.error('Critical: Default employee role not found in database');
        throw new NotFoundException('Role "employee" not found');
      }

      // Create user
      const user = this.userRepository.create({
        firstName,
        lastName,
        email,
        password: await bcrypt.hash(password, 10),
        roles: [role],
      });

      await this.userRepository.save(user);

      // Success log - sadece ID ile
      this.logger.log(`User created successfully with ID: ${user.id}`);
      return { message: 'User created successfully' };

    } catch (error) {
      if (error instanceof BadRequestException || error instanceof NotFoundException) {
        throw error;
      }

      this.logger.error(`Unexpected error creating user: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to create user');
    }
  }

  // GET ALL USERS - Loglama kaldırıldı (yüksek frekanslı işlem)
  async findAll(): Promise<User[]> {
    try {
      return await this.userRepository.find({ relations: ['roles'] });
    } catch (error) {
      this.logger.error(`Failed to retrieve users: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to retrieve users');
    }
  }

  // GET ONE USER - Sadece hata durumunda log
  async findOne(id: number): Promise<User> {
    try {
      const user = await this.userRepository.findOne({
        where: { id },
        relations: ['roles'],
      });

      if (!user) {
        this.logger.debug(`User not found with ID: ${id}`);
        throw new NotFoundException('User not found');
      }

      return user;

    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(`Error fetching user with ID ${id}: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to fetch user');
    }
  }

  // SOFT DELETE
  async delete(id: number): Promise<{ message: string }> {
    try {
      const user = await this.userRepository.findOne({ where: { id } });

      if (!user) {
        this.logger.debug(`Soft delete failed - User not found with ID: ${id}`);
        throw new NotFoundException('User not found');
      }

      await this.userRepository.softDelete(id);

      this.logger.log(`User soft deleted with ID: ${id}`);
      return { message: 'User soft deleted successfully' };

    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(`Error during soft delete for user ID ${id}: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to delete user');
    }
  }

  // HARD DELETE
  async hardDelete(id: number): Promise<{ message: string }> {
    try {
      const user = await this.userRepository.findOne({ where: { id } });

      if (!user) {
        this.logger.debug(`Hard delete failed - User not found with ID: ${id}`);
        throw new NotFoundException('User not found');
      }

      await this.userRepository.delete(id);

      // Critical operation - log required
      this.logger.warn(`User HARD DELETED with ID: ${id}`);
      return { message: 'User hard deleted successfully' };

    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(`Error hard deleting user ID ${id}: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to hard delete user');
    }
  }

  // RESTORE
  async restore(id: number): Promise<{ message: string }> {
    try {
      const user = await this.userRepository.findOne({ where: { id }, withDeleted: true });

      if (!user) {
        this.logger.debug(`Restore failed - User not found with ID: ${id}`);
        throw new NotFoundException('User not found');
      }

      await this.userRepository.restore(user.id);
      this.logger.log(`User restored with ID: ${id}`);
      return { message: 'User restored successfully' };

    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(`Error restoring user ID ${id}: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to restore user');
    }
  }

  // DISABLE USER
  async disableUser(id: number): Promise<{ message: string }> {
    try {
      const user = await this.userRepository.findOne({ where: { id } });

      if (!user) {
        this.logger.debug(`Disable failed - User not found with ID: ${id}`);
        throw new NotFoundException('User not found');
      }

      if (!user.isActive) {
        this.logger.debug(`User already disabled with ID: ${id}`);
        throw new BadRequestException('User is already disabled');
      }

      user.isActive = false;
      await this.userRepository.save(user);

      this.logger.log(`User disabled with ID: ${id}`);
      return { message: 'User disabled successfully' };

    } catch (error) {
      if (error instanceof NotFoundException || error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error(`Error disabling user ID ${id}: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to disable user');
    }
  }

  // ENABLE USER 
  async enableUser(id: number): Promise<{ message: string }> {
    try {
      const user = await this.userRepository.findOne({ where: { id } });

      if (!user) {
        this.logger.debug(`Enable failed - User not found with ID: ${id}`);
        throw new NotFoundException('User not found');
      }

      if (user.isActive) {
        this.logger.debug(`User already enabled with ID: ${id}`);
        throw new BadRequestException('User is already enabled');
      }

      user.isActive = true;
      await this.userRepository.save(user);

      this.logger.log(`User enabled with ID: ${id}`);
      return { message: 'User enabled successfully' };

    } catch (error) {
      if (error instanceof NotFoundException || error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error(`Error enabling user ID ${id}: ${error.message}`, error.stack);
      throw new InternalServerErrorException('Failed to enable user');
    }
  }

  // UPDATE USER
  @Transactional()
  async updateUser(id: number, updateUserDto: UpdateUserDto): Promise<{ message: string }> {
    try {
      const user = await this.userRepository.findOne({ where: { id } });

      if (!user) {
        this.logger.debug(`Update failed - User not found with ID: ${id}`);
        throw new NotFoundException('User not found');
      }

      // Email güncelleme kontrolü
      if (updateUserDto.email && updateUserDto.email.toLowerCase() !== user.email) {
        const exists = await this.userRepository.findOne({
          where: { email: updateUserDto.email.toLowerCase() }
        });
        if (exists) {
          this.logger.warn(`Update failed - Email conflict for user ID: ${id}`);
          throw new ConflictException('Email already in use');
        }
        user.email = updateUserDto.email.toLowerCase();
      }

      // Field updates
      if (updateUserDto.firstName !== undefined) user.firstName = updateUserDto.firstName;
      if (updateUserDto.lastName !== undefined) user.lastName = updateUserDto.lastName;

      // Password update
      if (updateUserDto.password) {
        if (updateUserDto.confirmPassword !== updateUserDto.password) {
          this.logger.warn(`Update failed - Password mismatch for user ID: ${id}`);
          throw new BadRequestException('Passwords do not match');
        }
        user.password = await bcrypt.hash(updateUserDto.password, 10);
      }

      await this.userRepository.save(user);

      this.logger.log(`User updated with ID: ${id}`);
      return { message: 'User updated successfully' };

    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw error instanceof HttpException ? error : new InternalServerErrorException('Failed to update user');
    }
  }

  // UPDATE USER ROLE
  @Transactional()
  async updateUserRole(id: number, updateUserRoleDto: UpdateUserRoleDto): Promise<{ message: string }> {
    try {
      const user = await this.userRepository.findOne({ where: { id } });

      if (!user) {
        this.logger.debug(`Update failed - User not found with ID: ${id}`);
        throw new NotFoundException('User not found');
      }

      const roles = await this.roleRepository.findBy({ name: In(updateUserRoleDto.roles) });
      user.roles = roles;
      await this.userRepository.save(user);

      this.logger.log(`User role updated with ID: ${id}`);
      return { message: 'User role updated successfully' };

    } catch (error) {
      this.logger.error(`Error updating user role for user ID ${id}: ${error.message}`, error.stack);
      throw error instanceof HttpException ? error : new InternalServerErrorException('Failed to update user role');
    }
  }

  // Utility method - Email masking for privacy
  private maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    return `${local.slice(0, 2)}***@${domain}`;
  }
}