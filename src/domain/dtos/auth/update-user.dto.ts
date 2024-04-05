import { Validators } from "../../../config";




export class UpdateUserDto {


  private constructor(
    public id: string,
    public name?: string,
    public email?: string,
    public password?: string,
    public role?: string[],
    public img?: string,
  ) { }

  static create(object: { [key: string]: any }): [string?, UpdateUserDto?] {
    const { id, name, email, password, role, img } = object;

    if (!id) return ['Missing id'];
    if (!Validators.isMongoID(id)) return ['Invalid Id']
    if (email && !Validators.email.test(email)) return ['Invalid email'];
    if (password && password.length < 6) return ['Password must be at least 6 characters'];
    let emailLowerCase
    if (email) {
      emailLowerCase = email.toLowerCase();
    }

    return [undefined, new UpdateUserDto(id, name, emailLowerCase, password, role, img)];
  }
}
