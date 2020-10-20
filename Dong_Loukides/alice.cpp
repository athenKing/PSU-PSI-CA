#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>

#include <libOTe/Tools/Tools.h>
#include <libOTe/Base/SimplestOT.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"

#include "cJSON.h"
#include "bloom.h"
#include "functions.h"
#include <math.h>
#include "timing.h"/* URL: https://github.com/barrust/timing-c */

using namespace osuCrypto;
using namespace std;

void sumAll(u32 batchNum,vector<block> &recvMsg,vector<bool> &isLastEven,
			vector<mpz_class> &randomSum,mpz_class modular){

	u32 byteLength = 16;
	for(u32 k=0;k<batchNum;k++){
		block cur = recvMsg[k];
		string lastRecvHex = binary2HexString((u8*)&cur,byteLength);
		isLastEven[k] = evenJudge(lastRecvHex);
		mpz_class random = mpz_class(lastRecvHex,16);
		randomSum[k] += random;
		randomSum[k] %= modular;
	}
}

int main(int argc, char *argv[])
{
	IOService ios;
	Session server(ios, "127.0.0.1", 1212, SessionMode::Server);
	Channel channel = server.addChannel();
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	Timing tm0;
    timing_start(&tm0);


	//step1. initiate basic parameters
	FILE *fp;
    fp = fopen("parameters.in", "r");
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);/* same as rewind(f); */
	char *content =(char *)malloc(fsize + 1);
	fread(content, 1, fsize, fp);
	fclose(fp);
	cJSON *config = cJSON_Parse(content);
	cJSON *flajolet = cJSON_GetObjectItemCaseSensitive(config, "flajolet");
	free(content);

	u32 lambda =cJSON_GetObjectItemCaseSensitive(config, "lambda")->valueint;
	u64 numOTs = cJSON_GetObjectItemCaseSensitive(flajolet, "wLen")->valueint;
	u32 otSecure = cJSON_GetObjectItemCaseSensitive(flajolet, "secureParameter")->valueint;
	u32 batchNum = cJSON_GetObjectItemCaseSensitive(flajolet, "hashingBatchNum")->valueint;
	cJSON_Delete(config);

	std::vector<uint32_t> fmSketch = load_Data_into_FM(batchNum,numOTs,"data/alice.data");

	
    timing_end(&tm0);
    printf("\nAlice finished generate her fmsketch in %f seconds!\n", timing_get_difference(tm0));

	
	u8 byteLength = 16;
	mpz_t MODULAR;
    mpz_init(MODULAR);
    mpz_set_ui(MODULAR,1);
    mpz_mul_2exp(MODULAR,MODULAR,lambda);
    mpz_class modular = mpz_class(MODULAR);

	vector<mpz_class> randomSum(batchNum);
	for(u32 i=0;i<batchNum;i++){
		randomSum.at(i)=0;
	}
    vector<bool> isLastEven(batchNum);


	//step1.initiate first round OT(1-2) process
	string firstBitString(batchNum,'0');
	for(u32 k=0;k<batchNum;k++){
		if(fmSketch[k] >> (batchNum-1))
			firstBitString[k]= '1';
	}
    BitVector choices = BitVector(firstBitString);
    std::vector<block> recvMsg(batchNum);
    IknpOtExtReceiver iknpRecv;
	iknpRecv.receiveChosen(choices, recvMsg, prng0, channel);


    sumAll(batchNum,recvMsg,isLastEven,randomSum,modular);


	//step2.initiate one OT(1-4) process
    u32 inputSize = 2;
    OosNcoOtReceiver recv;
    recv.configure(false, otSecure, inputSize);

    //step2_1. set baseot information
    std::vector<std::array<block, 2>> baseSend(recv.getBaseOTCount());
    channel.recv(baseSend);
    recv.setBaseOts(baseSend, prng0, channel);

    //step2_2. execuate OT(1_4) cycles
    for(u32 i=1;i<numOTs;i++){
	   	vector<block> recvMessage(batchNum);
	    vector<u64> choices(batchNum);
		for(u32 k=0;k<batchNum;k++){
		    u32 high = (isLastEven[k]) ? 0:2;
		    u32 low = ((fmSketch[k] >> (batchNum-1-i)) & 1);
		   	choices[k] = high + low;
		}
	    recv.receiveChosen(4, recvMessage, choices, prng0, channel);
	    sumAll(batchNum,recvMessage,isLastEven,randomSum,modular);
	}

    vector<array<char,32>> outputStrings(batchNum);
    channel.recv(outputStrings);

	mpz_class result;
    float average = 0.0f;
	for(u32 k=0;k<batchNum;k++){
		string tempStr(32,'0');
		for(u32 i=0;i<32;i++){
    		tempStr[i] = outputStrings[k][i];
    	}

		result = mpz_class(tempStr,16);
		result += randomSum[k];
		result %= modular;
		// cout<<k<<" cycle "<<result.get_ui()<<endl;
		average += result.get_ui(); 
	}

	average = average/(float)batchNum;

    cout<<"final average is: "<<round(pow(2,average)/.77351f)<<endl;

	channel.close();
    server.stop();
    ios.stop();
	return 1;
}


