
export interface AksaraCrypto {
    encrypt(data: string, customPublicKey?: string): string | false;
    decrypt(data: string, customPrivateKey?: string): string | false;
}
