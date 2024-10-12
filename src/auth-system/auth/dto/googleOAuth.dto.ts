import { IsNotEmpty, IsString } from "class-validator";

export class GoogleOAuthDto {
    @IsString()
    @IsNotEmpty()
    id_token: string;
}