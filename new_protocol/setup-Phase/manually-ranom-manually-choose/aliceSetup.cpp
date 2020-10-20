#include "config.h"
using namespace osuCrypto;

int main(int argc, char *argv[])
{
	IOService ios;
	Session server(ios, "127.0.0.1", 1212, SessionMode::Server);
	Channel recvChannel = server.addChannel();
	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	
	//precomputing OT
	uint32_t numOTs = BLOCKSIZE;

    std::vector<block> recvMsg(numOTs);
    BitVector choices = BitVector(numOTs);
    choices.randomize(prng0);


    std::vector<uint8_t> choiceInByte(numOTs);

    for(int i=0;i<numOTs;i++)
    	choiceInByte.at(i) = choices[i];


    FILE *fp = fopen("aliceChoices.bin","wb");
    fwrite(choiceInByte.data(),1,choiceInByte.size(),fp);
    fclose(fp);

   
	IknpOtExtReceiver recv;
	recv.receiveChosen(choices, recvMsg, prng0, recvChannel);

	FILE *fp1 = fopen("aliceRecvMsg.bin" , "wb" );
    fwrite(recvMsg.data(),1,recvMsg.size()*sizeof(block),fp1);
    fclose(fp1);

	recvChannel.close();
    server.stop();
    ios.stop();
	return 1;
}


