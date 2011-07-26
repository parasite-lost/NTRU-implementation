#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ntru.h"
#include "ntrulowlevel.h"
#include "ntrutest.h"



int main(int argc, char **argv)
{
	if(argc > 1)
	{
		/* test lowlevel functions */
		if(!strcmp(argv[1], "--test"))
			return testlowlevel();
		if(!strcmp(argv[1], "--ntru"))
			return testntru();
	}
	return 0;
}

