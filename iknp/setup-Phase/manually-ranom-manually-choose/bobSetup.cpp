#include "config.h"
using namespace osuCrypto;

int main(int argc, char *argv[])
{	
	Timing tm;
    timing_start(&tm);

	IOService ios;
	Session client(ios, "127.0.0.1", 1212, SessionMode::Client);
	Channel sendChannel = client.addChannel();
	PRNG prng1(_mm_set_epi32(253233465, 334565, 0, 235));

	uint32_t numOTs = BLOCKSIZE;
    std::vector<std::array<block, 2>> sendMsg(numOTs);
	prng1.get(sendMsg.data(),sendMsg.size());

	//step4.execuate iknp process
	IknpOtExtSender sender;
	sender.sendChosen(sendMsg, prng1, sendChannel);

	FILE *fp = fopen("bobRndMsg.bin" , "wb" );
    fwrite(sendMsg.data(),1,sendMsg.size()*2*sizeof(block),fp);
    fclose(fp);


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


