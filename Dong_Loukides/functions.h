#include <gmp.h>
#include <gmpxx.h>

#include "bloom.h"
#include <iostream>
#include <vector>
#include <cryptoTools/Common/Defines.h>

using namespace std;
using namespace osuCrypto;

std::vector<uint32_t> load_Data_into_FM(size_t vectorSize,u32 stringLength,const char *filepath);

std::string binary2HexString(unsigned char *src,int lenBytes);

void hexString2BinaryData(unsigned char *des,size_t lenDes,char *src,int lenSrc);

bool evenJudge(std::string &str);


