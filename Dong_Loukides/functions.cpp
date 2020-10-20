#include "functions.h"
#include <assert.h>
// #include <openssl/evp.h>
#include "murmur3.h"

static const char hexMapping[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

/* private function definitions */
std::vector<uint32_t> load_Data_into_FM(size_t vectorSize,u32 stringLength,const char *filepath){
    std::vector<uint32_t> fmSketch;
    std::string initialString(stringLength,'0');

    for(u32 i=0;i<vectorSize;i++){
        fmSketch.push_back(0);
    }

    FILE *fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open file %s!\n", filepath);
    }

    u32 outputLength;
    u32 usedBytesLen = (stringLength+7)/8;
    uint32_t hashOutput;    /* Output for the hash */

    while ((read = getline(&line, &len, fp)) != -1) {
        char *strip = line+1;
        strip[strlen(strip)-1]=0;
        char * pch= strtok(strip,", ");

        while (pch != NULL)
          {
            for(u32 k=0;k<vectorSize;k++){

                MurmurHash3_x86_32(pch, strlen(pch), k, &hashOutput);
                uint32_t curValue = (0x80000000 >> __builtin_clz(hashOutput));
                fmSketch[k] |= curValue;
            }
            pch = strtok(NULL, ", ");
          }
    }
    fclose(fp);
    if (line)
    free(line);

    // cout<<"bob cout is "<<eleCount<<endl;
    return fmSketch;
}

std::string binary2HexString(unsigned char *src,int lenBytes){
    char *temp = (char *)malloc(lenBytes*2);
    memset(temp,0,lenBytes*2);
    for(int i=0;i<lenBytes;i++){
        for(short j=1;j>=0;j--){
            temp[2*i+(1-j)] = hexMapping[ (*(src+i)>>(4*j)) & 15 ];
        }
    }
    std::string ret = std::string(temp,lenBytes*2);
    free(temp);
    return ret;
}

int hexchr2bin(const char hex)
{
    // assert((hex >= '0' && hex <= '9') or (hex >= 'A' && hex <= 'F') or (hex >= 'a' && hex <= 'f'));
    int ret;
    if (hex >= '0' && hex <= '9') {
        ret = hex - '0';
    } else if (hex >= 'A' && hex <= 'F') {
        ret = hex - 'A' + 10;
    } else if (hex >= 'a' && hex <= 'f') {
        ret = hex - 'a' + 10;
    } else {
        return 0;
    }
    return ret;
}

void hexString2BinaryData(unsigned char *des,size_t lenDes,char *src,int lenSrc){
    if(lenSrc%2 ==0){
        int offset = lenDes - lenSrc/2;

        for(int i=0;i<lenSrc/2;i++){
            int convert = (hexchr2bin(*(src+i*2))<<4 )+ hexchr2bin(*(src+i*2+1));
            *(des+offset+i) = convert;
        }
    }else{
        int offset = lenDes - (lenSrc-1)/2;
        *(des+offset-1) = hexchr2bin(*src);
        for(int i=0;i<(lenSrc-1)/2;i++){
            *(des+offset+i) = (hexchr2bin(*(src+1+i*2))<<4 )+ hexchr2bin(*(src+i*2+2));
        }
    }
}


bool evenJudge(string &str){
    const char hex = str.back();

    assert((hex >= '0' && hex <= '9') or (hex >= 'A' && hex <= 'F') or (hex >= 'a' && hex <= 'f'));

    u32 ret;

    if (hex >= '0' && hex <= '9') {
        ret = hex - '0';
    } else if (hex >= 'A' && hex <= 'F') {
        ret = hex - 'A' + 10;
    } else if (hex >= 'a' && hex <= 'f') {
        ret = hex - 'a' + 10;
    }

    return (ret%2 == 0 );
}