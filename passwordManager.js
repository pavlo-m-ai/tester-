import argon2 from 'argon2';
import fs from 'fs';

const FILE_PATH = 'password_hash.txt';

export function createPasswordManager({ hasher = argon2, fileSystem = fs } = {}) {
    return {
        async savePassword(password) {
            const hash = await hasher.hash(password);
            fileSystem.writeFileSync(FILE_PATH, hash);
            fileSystem.chmodSync(FILE_PATH, 0o444);
        },

        hashFileExists() {
            return fileSystem.existsSync(FILE_PATH);
        },

        readHashFromFile() {
            try {
                fileSystem.chmodSync(FILE_PATH, 0o444);
                return fileSystem.readFileSync(FILE_PATH, 'utf8').trim();
            } catch (err) {
                throw new Error('Помилка читання файлу');
            }
        },

        async verifyPassword(storedHash, inputPassword) {
            try {
                return await hasher.verify(storedHash, inputPassword);
            } catch {
                throw new Error('Файл містить недійсний хеш');
            }
        }
    };
}
