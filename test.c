#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/******************************************************************************
 * Program takes an input and produces the SHA256 of it the input 
 *****************************************************************************/
int main(int argc, char **argv)
{	
	if(argc<2)
	{
		puts("Usage: ./test: message\n");
		return 0;
	}
	
	
	WORD *result = sha256((unsigned char *)argv[1],strlen(argv[1]));
	print_H(result);
	return 1;

}
