#include <random>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>

#include <libOTe/Tools/Tools.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>

#include "cJSON.h"
#include "functions.h"
#include "Paillier.h"
#include "timing.h"  /* URL: https://github.com/barrust/timing-c */
#include <math.h>


using namespace osuCrypto;

int main(int argc, char *argv[])
{	
	Timing tm;
    timing_start(&tm);

	IOService ios;
	Session client(ios, "127.0.0.1", 1212, SessionMode::Client);
	Channel sendChannel = client.addChannel();
	PRNG prng1(_mm_set_epi32(253233465, 334565, 0, 235));

	//step1. building bloom filters
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


	u32 lambda = cJSON_GetObjectItemCaseSensitive(config, "lambda")->valueint;
	u32 mLen = cJSON_GetObjectItemCaseSensitive(iknp, "mLen")->valueint;

	BloomFilter bf;
	BloomFilter *ptrBF=&bf;
    bloom_filter_init(ptrBF, 
    	cJSON_GetObjectItemCaseSensitive(iknp, "bf_capacity")->valueint,
    	cJSON_GetObjectItemCaseSensitive(iknp, "bf_errorRate")->valuedouble);


   	int arrayLength = load_Data_into_BF(ptrBF, "../data/bob.data");
    bloom_filter_stats(ptrBF);
	cJSON_Delete(config);
	u32 hashNum = ptrBF->number_hashes;
	u32 bytesLen = mLen/8;
	u32 numOTs = ptrBF->number_bits;
	u32 strLength = bytesLen*2+2;//mpz_get_str method requires two more bytes allocation
	double bits_per_slice =(double) numOTs/hashNum;//m/k


	mpz_t randomSum;
	mpz_init(randomSum);

	mpz_t modular;
    mpz_init(modular);
    mpz_set_ui(modular,1);
    mpz_mul_2exp(modular,modular,mLen);

    //step2: receive seeming randomly e arrays to permute messages
    std::vector<uint8_t> bitsOrder(numOTs);
    sendChannel.recv(bitsOrder);
	// std::cout<<"step1. receive "<<numOTs<<" bitorder"<<std::endl;


    //step3. prepare and permute message pairs
    std::vector<std::array<block, 2>> sendMsg(numOTs);
    std::vector<std::array<block, 2>> preMsg(numOTs);

    FILE *pFile = fopen("../setup-Phase/bobRndMsg.bin","rb");
    fread(preMsg.data(),1,preMsg.size()*2*sizeof(block),pFile);
    fclose(pFile);

    std::string bfBits = binary2BinString((u8*)ptrBF->bloom,numOTs);

    for(u32 i=0;i<numOTs;i++){
    	//we calculate the all zero number share
    	if( bfBits.at(i) == '1' ){
    		bfBits.at(i) = '0';
    	}
    	else{
    		bfBits.at(i) = '1';
    	}

    	char binaryRandom[100]={0};
		prng1.get((u8*)binaryRandom,bytesLen);

		std::string binaryHexString = binary2HexString((u8*)binaryRandom,bytesLen);

		mpz_t random;
		mpz_init(random);
		mpz_set_str(random,binaryHexString.c_str(),16);
		mpz_add(randomSum,random,randomSum);//add random onto randomSum

		mpz_add_ui(random,random,1);
		mpz_mod(random,random,modular);
		char *hexString1 = (char *)malloc(strLength);
		memset(hexString1,0,strLength);
		mpz_get_str(hexString1,16,random);
		unsigned char *binaryRandomAdd = (unsigned char *)malloc(bytesLen);
		memset(binaryRandomAdd,0,bytesLen);
		hexString2BinaryData(binaryRandomAdd,bytesLen,hexString1,strlen(hexString1));

		block blockr = toBlock((u8 *)binaryRandom);
		block blockr1 = toBlock(binaryRandomAdd);

		sendMsg[i][0] = preMsg[i][bitsOrder.at(i)] ^  blockr;
		sendMsg[i][1] =  preMsg[i][1-bitsOrder.at(i)] ^ ((bfBits.at(i) == '1') ? blockr1:blockr);

		mpz_clear(random);
		free(hexString1);
		free(binaryRandomAdd);

		if(i%10 == 0)
		mpz_mod(randomSum,randomSum,modular);
    }
    bloom_filter_destroy(ptrBF);
	
	//step4.directly send these message pairs
	sendChannel.send(sendMsg);//Just directly send message pairs

	//step5.calcualte algorithms
	mpz_mod(randomSum,randomSum,modular);
	mpz_sub(randomSum,modular,randomSum);

	if(CALCULATE_UNION){
		//step6.send the final calculation result
		char *outputStr = (char *)malloc(strLength);
		memset(outputStr,0,bytesLen*2);
	    mpz_get_str(outputStr,16,randomSum);
	    mpz_clear(randomSum);
		
		std::string outputString(outputStr);
		sendChannel.send(outputString);
		free(outputStr);
	}
	else{
    	uint32_t pubKeyLen = 3;

        mpz_t unionVal[1];
	    mpz_init(unionVal[0]);

	    mpz_t pubKeys[pubKeyLen];
	    for(int i=0;i<pubKeyLen;i++){
	        mpz_init(pubKeys[i]);
	    }


	    //Round1: receive cipherData and combine meaningful data, and do some obfuscation
	    //<-----Round1-1: receive enc(m0)----->
	    std::vector<unsigned char> receiveVector;
	    sendChannel.recv(receiveVector);
	    unsigned char* receiveBuff = &receiveVector[0];
	    binaryData_to_mpzArray(receiveBuff,1,unionVal);
	    //<-----Round1-1: receive enc(m0)----->



	    //<-----Round1-2: receive Pallier PK----->
	    std::vector<unsigned char> pubKeysVector;
	    sendChannel.recv(pubKeysVector);
	    unsigned char* receiveBuff1 = &pubKeysVector[0];
	    binaryData_to_mpzArray(receiveBuff1,pubKeyLen,pubKeys);
	    //<-----Round1-2: receive Pallier PK----->


	    //<-----Round1-3: HomoAdd to get enc(m0+m1)----->
		paillier_encryption(randomSum,pubKeys);
	    mpz_mul(unionVal[0],unionVal[0],randomSum);
		mpz_mod(unionVal[0],unionVal[0],pubKeys[2]);
	    //<-----Round1-3: HomoAdd to get enc(m0+m1)----->

	    //<-----Round1-4: prepare multi*RandomSum scale----->
		u32 randomOffsetBytesLen = 8;
	    char tempString[100]={0};
    	mpz_t random_offset;
		mpz_init(random_offset);
		prng1.get((u8*)tempString,randomOffsetBytesLen);
		std::string binaryHexString = binary2HexString((u8*)tempString,randomOffsetBytesLen);


		mpz_set_str(random_offset,binaryHexString.c_str(),16);
	    uint32_t multi = round(PRECISION_FACTOR*exp(arrayLength*hashNum/(float)numOTs));
	    // printf("The multi factor multi is: %d \n",multi);
	    mpz_t exponent;
	    mpz_init(exponent);
	    mpz_mul_ui(exponent,random_offset,multi);
	    // gmp_printf ("\n\nThe exponent message: \n%Zx\n", exponent);
	    mpz_powm(unionVal[0],unionVal[0],exponent,pubKeys[2]);
	    //<-----Round1-4: prepare multi*RandomSum scale----->


	    //<-----Round2-1: send result to the other party----->
	    char intersectChar[1000];
	    mpz_get_str(intersectChar,16,unionVal[0]);
	    sendChannel.send(std::vector<char>(intersectChar, intersectChar + strlen(intersectChar)));
	    //<-----Round2-1: send result to the other party----->


	    //Round3: receive plaintext and add it to our offset to decrypt the final data
	    //<-----Round3-1: receive that data----->
	    mpz_t finalVal;
	    mpz_init(finalVal);
	    std::vector<char> receiveVector2;
	    sendChannel.recv(receiveVector2);
	    mpz_set_str(finalVal,&receiveVector2[0],16);
	    uint64_t interSectionResult = mpz_get_ui(finalVal);
	    mpz_clear(finalVal);
	    //<-----Round3-1: receive that data----->
	    

	    //<-----Round3-2: calculate the random offset----->
	    signed long int exp2;
		double expBase2 = mpz_get_d_2exp(&exp2,random_offset);
		double part1 = exp2*log(2)+log(expBase2);
		part1 = bits_per_slice*part1;
	    uint64_t offsetRecovery = round(part1);
	    interSectionResult = interSectionResult - offsetRecovery;
	    //<-----Round3-2: calculate the random offset----->

	    std::cout<<"offsetRecovery is: "<<offsetRecovery<<std::endl;
	    std::cout<<"final intersection estimate is: "<<interSectionResult<<std::endl;

	    mpz_clear(exponent);
	    mpz_clear(random_offset);
	    MPZ_CLEAR(unionVal,1);
	    MPZ_CLEAR(pubKeys,3);
	}


	char sentStatistics[100]={0};
    char receiveStatistics[100]={0};
    sprintf(sentStatistics,"%.2f MB",(float)sendChannel.getTotalDataSent()/(1<<20));
    sprintf(receiveStatistics,"%.2f MB",(float)sendChannel.getTotalDataRecv()/(1<<20));
	std::cout<< "   Session: " << sendChannel.getSession().getName() << std::endl
    << "      Sent: " << sentStatistics << std::endl
    << "  received: " << receiveStatistics << std::endl;
    sendChannel.resetStats();

	sendChannel.close();
    client.stop();
    ios.stop();


    timing_end(&tm);
    printf("\nCompleted iknp tests in %f seconds!\n", timing_get_difference(tm));
	return 1;
}


