import {JSEncrypt} from "jsencrypt";
import {AksaraCrypto} from "./crypto";

const PRIVATE_KEY_TYPE = "RSA PRIVATE KEY";
const PUBLIC_KEY_TYPE = "PUBLIC KEY";

class RSACrypto implements AksaraCrypto {

    private encryptor: JSEncrypt
    private privateKey: string
    private publicKey: string



    constructor(privateKey: string, publicKey: string) {
        this.encryptor = new JSEncrypt();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.encryptor.setPrivateKey(this.privateKey);
        this.encryptor.setPublicKey(this.publicKey);
    }

    static async create(privateKey: string, publicKey: string): Promise<RSACrypto> {
        return new RSACrypto(privateKey, publicKey);
    }

    encrypt(data: string, customPublicKey?: string): string | false {
        const pubKey = customPublicKey || this.publicKey;
        if (!pubKey) {
            throw new Error("Public key is not set");
        }
        if(customPublicKey) {
            this.encryptor.setPublicKey(customPublicKey);
        }

        return this.encryptor.encrypt(data);
    }

    decrypt(data: string, customPrivateKey?: string): string | false {
        const privKey = customPrivateKey || this.privateKey;
        if (!privKey) {
            throw new Error("Private key is not set");
        }
        if(customPrivateKey){
            this.encryptor.setPrivateKey(customPrivateKey);
        }

        return this.encryptor.decrypt(data);
    }
}

export { RSACrypto, PRIVATE_KEY_TYPE, PUBLIC_KEY_TYPE };
