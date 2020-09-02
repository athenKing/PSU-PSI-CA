#include "functions.h"
#include <assert.h>

static const char hexMapping[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};


/* private function definitions */
int load_Data_into_BF(BloomFilter *bf,const char *filepath) {
    FILE *fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open file %s!\n", filepath);
        return 0;
    }

    int elementCount=0;

    while ((read = getline(&line, &len, fp)) != -1) {
        char *strip = line+1;
        strip[strlen(strip)-1]=0;

        char * pch= strtok(strip,", ");
        while (pch != NULL)
          {
            elementCount++;
            bloom_filter_add_string(bf, pch);
            pch = strtok(NULL, ", ");
          }
    }
    fclose(fp);
    if (line)
    free(line);

    return elementCount;
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


std::string binary2BinString(unsigned char *src,int lenBits){
    int lenBytes = (lenBits+7)/8;

    std::string ret;

    for(int j=0;j<lenBytes;j++){
        unsigned char *cur =src + j;

        int slice;
        if(j < (lenBytes-1) )
            slice=7;
        else
            slice=lenBits-(lenBytes-1)*8-1;

        for(int i=slice;i>=0;i--){
            if((*cur>>i) & 1)
                ret.push_back('1');
            else
                ret.push_back('0');
        }
    }
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

void binaryData_to_mpzArray(unsigned char* binaryData,int outPutLen,mpz_t *outPut){
    unsigned char* temp=binaryData+4;
    for(int i = 0; i<outPutLen; i++)
    {
        int countBytes = *((int *)temp);
        mpz_import(outPut[i],countBytes,1,1,1,0,temp+4);
        temp += (4+countBytes);
    }
}

void mpzArray_to_BinaryData(unsigned char** binaryData,mpz_t* data,int dataLen,int &byteCount,const char* toFilePath){
    size_t preAlloc= 4+ 4*dataLen;
    byteCount = preAlloc;

    for(int i = 0; i<dataLen; i++)
    {
        preAlloc += 8* data[i]->_mp_alloc;
    }

    
    *binaryData = (unsigned char *)malloc(preAlloc);
    memcpy(*binaryData,&dataLen,4);
    unsigned char* temp = *binaryData+4;

    for(int i = 0; i<dataLen; i++)
    {
        size_t count;
        unsigned char* data0 = (unsigned char *)mpz_export(temp+4,&count,1,1,1,0,data[i]);
        memcpy(temp,&count,4);
        temp += (count+4);
        byteCount += count;
    }

    if(toFilePath){
        FILE * pwFile;
        pwFile = fopen (toFilePath, "wb");
        fwrite (*binaryData , sizeof(unsigned char), byteCount, pwFile);
        fclose (pwFile);
    }
}