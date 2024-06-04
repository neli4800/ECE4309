// Include the necessary libraries
#include "seal/seal.h"
#include <gsl/gsl>
#include <iostream>


using namespace std;
using namespace seal;

std::string uint64_to_hex_string(uint64_t n) {
    std::stringstream ss;
    ss << std::hex << n;
    return ss.str();
}

int main()
{
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(1024);

    // Generate keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();


    // Encrypt the input numbers
    Encryptor encryptor(context, public_key);
    Plaintext x_plain("1"), y_plain("9");
    uint64_t z = 22;
    Plaintext z_plain(uint64_to_hex_string(z));
    Ciphertext x_encrypted, y_encrypted, z_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    encryptor.encrypt(z_plain, z_encrypted);

    // Perform computations on the encrypted data
    Evaluator evaluator(context);
    Ciphertext add_result_encrypted, mult_result_encrypted;
    evaluator.add(x_encrypted, y_encrypted, add_result_encrypted);
    evaluator.multiply(add_result_encrypted, z_encrypted, mult_result_encrypted);

    // Decrypt the result
    Decryptor decryptor(context, secret_key);
    Plaintext add_result_plain, mult_result_plain;
    decryptor.decrypt(add_result_encrypted, add_result_plain);
    decryptor.decrypt(mult_result_encrypted, mult_result_plain);

    // Convert the hexadecimal result to decimal
    int add_result_decimal = std::stoi(add_result_plain.to_string(), nullptr, 16);
    int mult_result_decimal = std::stoi(mult_result_plain.to_string(), nullptr, 16);
    

    // Print the result
    std::cout << "Addition Result: " << add_result_plain.to_string() << std::endl;

    std::cout << "Multiplication Result: " << mult_result_plain.to_string() << std::endl;
   
    // Print the result
    std::cout << "Addition Result Decimal: " << add_result_decimal << std::endl;
    std::cout << "Multiplication Result Decimal: " << mult_result_decimal << std::endl;

    return 0;
}
