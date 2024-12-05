#include "openfhe.h"
#include <iostream>

using namespace lbcrypto;

int main() {
    // Step 1: Set up the encryption system (BFV scheme)
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537); // Modulus for plaintext
    parameters.SetMultiplicativeDepth(2); // Depth for operations

    // Generate the crypto context
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features: Encryption and SHE (homomorphic evaluation)
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Step 2: Key generation
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey); // Support for multiplication

    // Step 3: Encryption of plaintext vectors
    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    std::vector<int64_t> vectorOfInts3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};

    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);
    Plaintext plaintext3 = cryptoContext->MakePackedPlaintext(vectorOfInts3);

    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
    auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);

    // Step 4: Homomorphic operations (Addition and Multiplication)
    auto ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
    auto ciphertextAddResult = cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);

    auto ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    auto ciphertextMultResult = cryptoContext->EvalMult(ciphertextMul12, ciphertext3);

    // Step 5: Decryption and results
    Plaintext plaintextAddResult, plaintextMultResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &plaintextAddResult);
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult, &plaintextMultResult);

    plaintextAddResult->SetLength(vectorOfInts1.size());
    plaintextMultResult->SetLength(vectorOfInts1.size());

    // Output results
    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;

    return 0;
}