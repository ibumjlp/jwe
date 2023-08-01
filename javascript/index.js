import * as jose from 'jose';

import PrivateKey from "./private_key.js";
import PublicKey from "./public_key.js";

const EncryptData = async (data) => {
    const ecPublicKey = await jose.importSPKI(PublicKey, 'RSA-OAEP-256');
    const jwe = await new jose.FlattenedEncrypt(new TextEncoder().encode(JSON.stringify(data)))
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256CBC-HS512' })
        .encrypt(ecPublicKey);
    return jwe;
}

const DecryptData = async (jwe) => {
    const ecPrivateKey = await jose.importPKCS8(PrivateKey, 'RSA-OAEP-256');
    const { plaintext } = await jose.flattenedDecrypt(jwe, ecPrivateKey);
    let decodedText = new TextDecoder('utf-8').decode(plaintext);
    return decodedText;
}

const convertJSONFormat = async (stringJSON) => {
    let newStringJSON = "";
    for (let i in stringJSON) {
        if (stringJSON[i] === "'") newStringJSON += '"';
        else if (stringJSON[i] === '"') newStringJSON += "'";
        else newStringJSON += stringJSON[i];
    }
    newStringJSON = newStringJSON.replaceAll("True", "true");
    newStringJSON = newStringJSON.replaceAll("False", "false");
    return newStringJSON;
}

const test = async () => {
    let data = {
        pid: "1111111111115"
    }
    const x = await EncryptData(data);
    console.log(x);
}

const dec = async () => {
    let data = {
        "ciphertext": "pIZHQmUG0w6o6m8ZKmC0kKIfjdTl1ksym9cnqw7f_Enf2uZjX6sd1VCr_-MmjEAwygKTkwRa2VomZnxfV3sfhQ",
        "encrypted_key": "LLMmsdq-2M_peQP1z3UGaJSzq5QleGz9kca38Q-H0zqiHogihAh70uUqcDqd3NE-PN5_iYLSamp99-HSWUrBCgtrgk6M6s4W5WGK-p2UV5Pt7pWlMa05dNaAkuGYHiSYm6YJV-DVdgfQlZD82eDWOlw7Zp80MGgKAlq3aWRANK5kJvt357Hmkowg5TzeQoHbOVxFYxqwZ_KkCoCAWrNj-n-O47I5AQxWoy8mIwfe8GF7Jpun39zidvtETaBaEZOsZsVrKy6XZji79cqx3guewSf3Dgb-aLFSL7UWCDZYZ9rA0BkH6XYnkR1J5Yx22QDEWRes45rA5dCdx86T3bhFng",
        "iv": "0QuKNnZ9erHZzjyI5waV5g",
        "protected": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidWtxeFZMOVgxWHpkTzZRUUljaHFtNGo5dE8ySnNwc2FrbmYtSWhmMjM3byIsInR5cCI6IkpXRSJ9",
        "tag": "jSpKGZ2kvJlPbtWpjsbxh3erBSR5H4DuwstQCzYg-Ng"
    }
    const x = await DecryptData(data);
    console.log(x);

}

test()