import { AuthRepository, GetAndDeleteUserDto } from "../..";


interface UserUpdate {
  user: {
    id: string;
    name: string;
    email: string;
  }
}


interface DeleteUserUseCase {
  execute(getAndDeleteUserDto: GetAndDeleteUserDto): Promise<UserUpdate>;
}

export class DeleteUser implements DeleteUserUseCase {

  constructor(
    private readonly authRepository: AuthRepository,
  ) { }

  async execute(getAndDeleteUserDto: GetAndDeleteUserDto): Promise<UserUpdate> {

    const user = await this.authRepository.delete(getAndDeleteUserDto);

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      }
    }
  }

}
