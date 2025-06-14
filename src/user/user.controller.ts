import { Controller, Post, Body, HttpCode, Delete, Param, ParseIntPipe, Get, Put } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entities/user.entity';
import { UpdateUserDto } from './dto/update-user.dto';
import { Roles } from 'src/common/decorators/roles.decorator';
import { UseGuards } from '@nestjs/common';
import { JwtGuard } from 'src/common/guards/JwtGuard';
import { RolesGuard } from 'src/common/guards/RolesGuard';
import { ApiBearerAuth } from '@nestjs/swagger';
import { UpdateUserRoleDto } from './dto/update-user-role.dto';

@Controller('users')
@UseGuards(JwtGuard, RolesGuard)
@Roles('admin')
@ApiBearerAuth() // SWAGGER İÇİN
export class UserController {
  constructor(private readonly userService: UserService) { }

  //CREATE USER
  @Post()
  @HttpCode(201)
  async createUser(@Body() createUserDto: CreateUserDto): Promise<{ message: string }> {
    return this.userService.create(createUserDto);
  }

  // DELETE USER
  @Delete(':id')
  @HttpCode(204)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<{ message: string }> {
    return this.userService.delete(id);
  }

  // GET ALL USER
  @Get()
  @HttpCode(200)
  async findAll(): Promise<User[]> {
    return this.userService.findAll();
  }

  //GET USER
  @Get(':id')
  @HttpCode(200)
  async findOne(@Param('id', ParseIntPipe) id: number): Promise<User> {
    return this.userService.findOne(id);
  }

  //DISABLE USER
  @Put(':id/disable')
  @HttpCode(204)
  async disableUser(@Param('id', ParseIntPipe) id: number): Promise<{ message: string }> {
    return this.userService.disableUser(id);
  }

  //ENABLE USER
  @Put(':id/enable')
  @HttpCode(204)
  async enableUser(@Param('id', ParseIntPipe) id: number): Promise<{ message: string }> {
    return this.userService.enableUser(id);
  }

  //HARD DELETE
  @Delete(':id/hard-delete')
  @HttpCode(204)
  async hardDelete(@Param('id', ParseIntPipe) id: number): Promise<{ message: string }> {
    return this.userService.hardDelete(id);
  }

  //UPDATE USER
  @Put(':id')
  @HttpCode(200)
  async updateUser(@Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto): Promise<{ message: string }> {
    return this.userService.updateUser(id, updateUserDto);
  }

  //UPDATE USER ROLE
  @Put(':id/role')
  @HttpCode(200)
  async changeUserRole(@Param('id', ParseIntPipe) id: number, @Body() updateUserRoleDto: UpdateUserRoleDto): Promise<{ message: string }> {
    return this.userService.updateUserRole(id, updateUserRoleDto);
  }
}
