// กำหนด Interface ให้ตรงกับสิ่งที่ JwtStrategy return กลับมา
export interface RequestWithUser {
  user: {
    userId: number;
    username: string;
    email: string;
    roles: string[];
  };
}