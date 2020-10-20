#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>

void paillier_getRandomPrime(mpz_t numrandom); /* 2^511 and 2^512 - 1 */

void paillier_getRandom(mpz_t numrandom); /* 2^511 and 2^512 - 1 */



void paillier_getPriKey (mpz_t KPri[3], mpz_t* LKey);
/* Private Keys: p, q and λ(n) */

void paillier_getPubKey (mpz_t KPub[3], mpz_t* LKey);
/* Public Keys: n, g and n^2 */




/*Key generatation*/
void paillier_generateKeys(mpz_t LKey[6]);



/*message encryption*/
// void paillier_encryption(mpz_t msg_secu, mpz_t m, mpz_t* KPub);
void paillier_encryption(mpz_t m, mpz_t* KPub);
/* msg_secu = g^m * r^n (mod n) */


/*message encryption*/
void paillier_decryption(mpz_t msg_clear, mpz_t msg_secu, mpz_t* KPub, mpz_t* KPri);
/* msg_clear = L(c^λ(n) (mod n^2)) / L(g^λ(n) (mod n^2)) (mod n) */



void paillier_lOfDecrypt(mpz_t resultL, mpz_t u, mpz_t* KPub);
/* L(u) = (u - 1) / n, ∀u ∈ Sn = {u | 0 < u < n^2 and u ≡ 1 (mod n)}  */

