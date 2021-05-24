import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { from, Observable } from 'rxjs';
import { User } from 'src/user/model/user.interface';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}

  generateJWT(payload: User): Observable<string> {
    return from(this.jwtService.signAsync({ user: payload }));
  }

  hashPassword(password: string): Observable<string> {
    return from<string>(bcrypt.hash(password, 12));
  }

  comparePasswords(newPassword: string, passwordHash: string): Observable<any> {
    return from(bcrypt.compare(newPassword, passwordHash));
  }
}
