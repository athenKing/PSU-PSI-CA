#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>

#include <libOTe/Tools/Tools.h>
#include <libOTe/Base/SimplestOT.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>

#include "cJSON.h"
#include "bloom.h"
#include "functions.h"
#include "Paillier.h"
#include <math.h>

using namespace osuCrypto;

int main(int argc, char *argv[])
{
	IOService ios;
	Session server(ios, "127.0.0.1", 1212, SessionMode::Server);
	Channel recvChannel = server.addChannel();
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	//step1. build Bloom Filter
	FILE *fp;
    fp = fopen("../data/parameters.in", "r");
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);/* same as rewind(f); */
	char *content =(char *)malloc(fsize + 1);
	fread(content, 1, fsize, fp);
	fclose(fp);
	cJSON *config = cJSON_Parse(content);
	cJSON *iknp = cJSON_GetObjectItemCaseSensitive(config, "iknp");
	free(content);
	u32 lambda =cJSON_GetObjectItemCaseSensitive(config, "lambda")->valueint;
	u32 mLen = cJSON_GetObjectItemCaseSensitive(iknp, "mLen")->valueint;
	BloomFilter bf;
	BloomFilter *ptrBF=&bf;

    bloom_filter_init(ptrBF, 
    	cJSON_GetObjectItemCaseSensitive(iknp, "bf_capacity")->valueint,
    	cJSON_GetObjectItemCaseSensitive(iknp, "bf_errorRate")->valuedouble);
   	int arrayLength = load_Data_into_BF(ptrBF, "../data/alice.data");
    // bloom_filter_stats(ptrBF);
    cJSON_Delete(config);
    
    u32 hashNum = ptrBF->number_hashes;
	u32 numOTs = ptrBF->number_bits;


	double bits_per_slice =(double) numOTs/hashNum;//m/k

    //we calculate the all zero number share,so choices are reversed
    BitVector choices = BitVector(binary2BinString((u8*)ptrBF->bloom,numOTs));
    bloom_filter_destroy(ptrBF);


    //step2. load precomuting data from local file(random receive message && random selected choice bits)
    std::vector<block> aliceRecvMsg(numOTs);
    FILE *pFile1 = fopen("../setup-Phase/aliceRecvMsg.bin","rb");
    fread(aliceRecvMsg.data(),1,aliceRecvMsg.size()*sizeof(block),pFile1);
    fclose(pFile1);


    std::vector<uint8_t> alicePreChoices( numOTs );
    FILE *pFile = fopen("../setup-Phase/aliceChoices.bin","rb");
    fread(alicePreChoices.data(),1,alicePreChoices.size(),pFile);
    fclose(pFile);

	//step3. send e = c ^ d to bob 
	for(int i=0;i<numOTs;i++){
	    alicePreChoices[i] = alicePreChoices[i] ^ ( 1- choices[i]);
	}
	recvChannel.asyncSend(std::move(alicePreChoices));

	//step4.receive obfuscated cipher pairs from bob,then does some calculation
    std::vector<std::array<block, 2>> finalRecv(numOTs);
    recvChannel.recv(finalRecv);

    u32 bytesLen = mLen/8;
	mpz_t modular;
    mpz_init(modular);
    mpz_set_ui(modular,1);
    mpz_mul_2exp(modular,modular,mLen);

    mpz_t aliceSum;
	mpz_init(aliceSum);

	for(int i=0;i<numOTs;i++)
	{	
		block x_c =  finalRecv.at(i)[1-choices[i]];
		aliceRecvMsg.at(i) = aliceRecvMsg.at(i) ^ x_c;

		block cur = aliceRecvMsg[i];
		std::string str = binary2HexString((unsigned char*)&cur,bytesLen);

		mpz_t random;
		mpz_init(random);
		mpz_set_str(random,str.c_str(),16);
		mpz_add(aliceSum,aliceSum,random);
		mpz_clear(random);
		
		if(i%10 ==0)
		mpz_mod(aliceSum,aliceSum,modular);
	}

	mpz_mod(aliceSum,aliceSum,modular);
	

	if(CALCULATE_UNION){
		mpz_t result;
		mpz_init(result);

		//step5. receive protocol partial results and sum these two partials
		std::string str1;
	    recvChannel.recv(str1);
	    mpz_set_str(result,str1.c_str(),16);
	    mpz_add(result,result,aliceSum);
		mpz_mod(result,result,modular);
		
		int intUnion = numOTs - mpz_get_ui(result);
		std::cout<<"final union is: "<<intUnion<<std::endl;
	    uint64_t ret = bloom_filter_estimate_elements_by_values(numOTs,intUnion,hashNum);
	    std::cout<<"final union estimate is: "<<ret<<std::endl;
	    mpz_clear(result);
	}else{
		mpz_t paillier_Keys[6];
	    mpz_t pubKey[3],priKey[3];
	    for(int i = 0; i < 6; i++)
	    {
	        mpz_init(paillier_Keys[i]);
	        if(i<3)
	        {
	            mpz_init(pubKey[i]);
	            mpz_init(priKey[i]);
	        }
	    }
	    paillier_generateKeys(paillier_Keys);
	    paillier_getPubKey(pubKey,paillier_Keys);
	    paillier_getPriKey(priKey,paillier_Keys);

	    //encrypt aliceSum
	    paillier_encryption(aliceSum,pubKey);
		mpz_t partialMessage[1];
	    mpz_init(partialMessage[0]);
	    mpz_set(partialMessage[0],aliceSum);


	    //Convert mpz data into binary data to transfer
	    unsigned char*cipherData;
	    int dataLength;

	    unsigned char*pubKeyData;
	    int pubBytesLen;
	    mpzArray_to_BinaryData(&cipherData,partialMessage,1,dataLength,NULL);
        mpzArray_to_BinaryData(&pubKeyData,pubKey,3,pubBytesLen,NULL);
        

	    //send enc(m1) & pubKey to the other party
	    std::vector<unsigned char> vecCipher = std::vector<unsigned char>(cipherData, cipherData + dataLength);
    	recvChannel.asyncSend(std::move(vecCipher));

	    //send alice's public pallier keys to bob
	    std::vector<unsigned char> vecPubKey = std::vector<unsigned char>(pubKeyData, pubKeyData + pubBytesLen);
	    recvChannel.asyncSend(std::move(vecPubKey));

	    //Receive enc(multi*(m0+m1))
	    std::vector<char> intersectRecv;
    	recvChannel.recv(intersectRecv);
	    mpz_t tmp;
	    mpz_init(tmp);
	    mpz_set_str(tmp,&intersectRecv[0],16);
	    paillier_decryption(tmp,tmp,pubKey,priKey);
		mpz_mod(tmp,tmp,modular);


		signed long int exp2;
		double expBase2 = mpz_get_d_2exp(&exp2,tmp);

		double part1 = exp2*log(2)+log(expBase2);
		part1 = bits_per_slice*part1;
	    double part2 = (double)arrayLength- bits_per_slice*log(numOTs*PRECISION_FACTOR);
	    uint64_t result = round(part1+part2);
		// printf("final result  is: %d\n",result );
	    mpz_set_ui(tmp,result);


		char intersectChar[100];
	    mpz_get_str(intersectChar,16,tmp);
	    // printf("send clearIntersect length is: %d \n",strlen(intersectChar));
	    //Round2: send calculation result to the other party
	    recvChannel.send(std::vector<char>(intersectChar, intersectChar + strlen(intersectChar)));


	    MPZ_CLEAR(partialMessage,1);
	    MPZ_CLEAR(pubKey,3);
	    MPZ_CLEAR(priKey,3);
	    mpz_clear(tmp);
	}


	mpz_clear(modular);
	mpz_clear(aliceSum);

	recvChannel.close();
    server.stop();
    ios.stop();
	return 1;
}


