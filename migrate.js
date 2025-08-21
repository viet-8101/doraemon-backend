import bcrypt from 'bcryptjs';

const plainUsername = 'Doraemon'; // <-- Thay bằng username bạn muốn
const plainPassword = 'DoraemonthichDorayaki!Dorayakingonquadi!'; // <-- Thay bằng mật khẩu bạn muốn

const saltRounds = 10; // Recommended salt rounds

// Hashing the username and password
const hashedUsername = bcrypt.hashSync(plainUsername, saltRounds);
const hashedPassword = bcrypt.hashSync(plainPassword, saltRounds);

console.log('--- Copy these values to your .env file ---');
console.log(`ADMIN_USERNAME_HASH=${hashedUsername}`);
console.log(`ADMIN_PASSWORD_HASH=${hashedPassword}`);
console.log('-------------------------------------------');
console.log('\nIMPORTANT: Remember to delete the plaintext password from this file and delete the file itself after use!');
