import { AuthDatasource, AuthRepository, LoginUserDto, RegisterUserDto, UpdateUserDto, UserEntity } from "../../domain";



export class AuthRepositoryImpl implements AuthRepository {

  constructor(
    private readonly authDatasource: AuthDatasource,
  ) {}
  update(updateUserDto: UpdateUserDto): Promise<UserEntity> {
    return this.authDatasource.update(updateUserDto);
  }
  login(loginUserDto: LoginUserDto): Promise<UserEntity> {
    return this.authDatasource.login(loginUserDto);
  }

  register(registerUserDto: RegisterUserDto): Promise<UserEntity> {
    return this.authDatasource.register(registerUserDto);
  }

}
