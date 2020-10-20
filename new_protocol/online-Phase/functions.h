#include <gmp.h>
#include "bloom.h"
#include <iostream>

#include <cryptoTools/Common/Defines.h>

#define PRECISION_FACTOR 10000

#define CALCULATE_UNION 0

// #define MPZ_CLEAR(X,Y) {if(Y == 1){mpz_clear(X);}else{ for(int i=0;i<Y;i++){mpz_clear(X[i]);} } }

#define MPZ_CLEAR(X,Y) for(int i=0;i<Y;i++){mpz_clear(X[i]);}


int load_Data_into_BF(BloomFilter *bf,const char *filepath);

std::string binary2HexString(unsigned char *src,int lenBytes);

std::string binary2BinString(unsigned char *src,int lenBits);

void hexString2BinaryData(unsigned char *des,size_t lenDes,char *src,int lenSrc);

void binaryData_to_mpzArray(unsigned char* binaryData,int outPutLen,mpz_t *outPut);

void mpzArray_to_BinaryData(unsigned char** binaryData,mpz_t* data,int dataLen,int &byteCount,const char* toFilePath);