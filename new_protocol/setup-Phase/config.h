#include <random>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>

#include <libOTe/Tools/Tools.h>
#include <libOTe/TwoChooseOne/SilentOtExtSender.h>
#include <libOTe/TwoChooseOne/SilentOtExtReceiver.h>

#include "timing.h"  /* URL: https://github.com/barrust/timing-c */


#define BLOCKSIZE 2500000