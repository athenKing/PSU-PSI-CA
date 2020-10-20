#include <random>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <libOTe/Tools/Tools.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"

#include "cJSON.h"
#include "functions.h"
#include "timing.h"/* URL: https://github.com/barrust/timing-c */

using namespace osuCrypto;
using namespace std;

void generateR0R1(PRNG &prng,block &r0,block &r1,
					vector<bool> &isLastEven,
					vector<mpz_class> &randomSum,u32 index,mpz_class modular){
	u8 byteLength = 16;
	char binary[50]={0};
	prng.get((u8*)binary,byteLength);
	r0 = toBlock((u8*)binary);

	std::string binaryHexString = binary2HexString((u8*)binary,byteLength);
	isLastEven[index] = evenJudge(binaryHexString);


	mpz_class random = mpz_class(binaryHexString,16);
	randomSum[index] += random;
	randomSum[index] %= modular;

	//generate r1 
	random += 1;
	random %= modular;
	string hexString = random.get_str(16);

	memset(binary,0,byteLength);
	hexString2BinaryData((u8*)binary,byteLength,(char *)hexString.c_str(),hexString.size());
	r1 = toBlock((u8*)binary);
}

int main(int argc, char *argv[])
{	
	Timing tm0;
    timing_start(&tm0);

	IOService ios;
	Session client(ios, "127.0.0.1", 1212, SessionMode::Client);
	Channel channel = client.addChannel();

	PRNG prng1(_mm_set_epi32(253233465, 334565, 0, 235));

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

	std::vector<uint32_t> fmSketch = load_Data_into_FM(batchNum,numOTs,"data/bob.data");

	timing_end(&tm0);
    printf("\nBob finished generate fmsketch in %f seconds!\n", timing_get_difference(tm0));

	Timing tm;
    timing_start(&tm);
	
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
	std::vector<std::array<block, 2>> sendMsg(batchNum);
	for(u32 k= 0;k<batchNum;k++){
		block r0,r1;
		generateR0R1(prng1,r0,r1,isLastEven,randomSum,k,modular);
		// sendMsg[k][0] = (fmSketch[k][0] == '1') ? r1:r0;
		sendMsg[k][0] = (fmSketch[k] >> (batchNum-1)) ? r1:r0;

		sendMsg[k][1] =  r1;
	}
    IknpOtExtSender iknpSender;
	iknpSender.sendChosen(sendMsg, prng1, channel);
	
	//step2.initiate remaining OT(1-4) process
    u32 inputSize = 2;
    OosNcoOtSender sender;
    sender.configure(false, otSecure, inputSize);


    //step3.Set baseot information
    u64 baseCount = sender.getBaseOTCount();
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    prng1.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng1);
    for (u64 k = 0; k < baseCount; ++k)
    {
        baseRecv[k] = baseSend[k][baseChoice[k]];
    }
    channel.asyncSend(baseSend);
    sender.setBaseOts(baseRecv,baseChoice,channel);
    

    //step4.set n-choose-1 batch chosen execuation
    for(u32 i=1;i<numOTs;i++){
        Matrix<block> sendMessage(batchNum,4);
        for(u32 k= 0;k<batchNum;k++){
			bool lastEven = isLastEven.at(k);
			block r0,r1;
			generateR0R1(prng1,r0,r1,isLastEven,randomSum,k,modular);
			if(lastEven){
	        	if (!( (fmSketch[k] >> (batchNum-1-i)) & 1 )){
	        	// if(fmSketch[k][i] == '0'){
	        		sendMessage[k][0] = r0;
	        		sendMessage[k][1] = r0;
	        		sendMessage[k][2] = r0;
	        		sendMessage[k][3] = r1;
	        	}
	        	else{
	        		sendMessage[k][0] = r0;
	        		sendMessage[k][1] = r0;
	        		sendMessage[k][2] = r1;
	        		sendMessage[k][3] = r1;
	        	}
	        }else{
	        	if (!( (fmSketch[k] >> (batchNum-1-i)) & 1 )){
	        	// if(fmSketch[k][i] == '0'){
	        		sendMessage[k][0] = r0;
	        		sendMessage[k][1] = r1;
	        		sendMessage[k][2] = r0;
	        		sendMessage[k][3] = r0;
	        	}
	        	else{
	        		sendMessage[k][0] = r1;
	        		sendMessage[k][1] = r1;
	        		sendMessage[k][2] = r0;
	        		sendMessage[k][3] = r0;
	        	}
	        }
		}
        sender.sendChosen(sendMessage, prng1, channel);
    }

    //step5.send uncharacteristic random sum values to the other party
    vector<array<char,32>> outputStrings(batchNum);
    for(u32 k= 0;k<batchNum;k++){
    	randomSum[k] = modular - randomSum[k];
    	string cur = randomSum[k].get_str(16);
    	u32 offset = 32 - cur.size();
    	for(u32 i=0;i<32;i++){
    		if(i<offset)
    		outputStrings[k][i]= '0';
    		else
    		outputStrings[k][i]= cur[i-offset];
    	}
    }

    channel.send(outputStrings);//TO-UNDERSTAND: async send would cause bug inside

	char sentStatistics[100]={0};
    char receiveStatistics[100]={0};
    sprintf(sentStatistics,"%.2f MB",(float)channel.getTotalDataSent()/(1<<20));
    sprintf(receiveStatistics,"%.2f MB",(float)channel.getTotalDataRecv()/(1<<20));
	std::cout<< "   Session: " << channel.getSession().getName() << std::endl
    << "      Sent: " << sentStatistics << std::endl
    << "  received: " << receiveStatistics << std::endl;
    channel.resetStats();

	channel.close();
    client.stop();
    ios.stop();

    timing_end(&tm);
    printf("\nCompleted online transfer in %f seconds!\n", timing_get_difference(tm));


    

	return 1;
}


