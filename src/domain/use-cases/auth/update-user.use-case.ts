import { AuthRepository, UpdateUserDto } from "../..";





interface UserUpdate {
  user: {
    id: string;
    name: string;
    email: string;
  }
}

interface UpdateUseUseCase {
  execute(updateUserDto: UpdateUserDto): Promise<UserUpdate>;
}


export class UpdateUser implements UpdateUseUseCase {

  constructor(
    private readonly authRepository: AuthRepository,
  ) { }

  async execute(updateUserDto: UpdateUserDto): Promise<UserUpdate> {

    const user = await this.authRepository.update(updateUserDto);

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      }
    }
  }
}
