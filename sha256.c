/***********************************INCLUDES**********************************/
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**********************************ABOUT************************************** 
 * This code provides functions to calculate the SHA256 of a string. It is    based on: 
https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf
*****************************************************************************/

/*********************************MACROS AS PART OF SHA256********************/
#define SHR(x, n) (x >> n)
#define SHL(x, n) (x << n)
#define ROTR32(x, n) (  (SHR(x, n)) | (SHL(x, (32 - n)))   )

#define CH(x, y, z) ((x & y) ^ (~(x) & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SUM0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))

#define SUM1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
				 
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR(x, 10))

/*****************************************************************************/





WORD *sha256(unsigned char *originalMessage, uint32_t length)
{
   /******************************************************************************
    * WORD *sha256(unsigned char *str, uint32_t length)
    * Description: 
	* 	- Take the input string and returns the sha256 digest. It first pads the 
	*	- input message, then loads into M, and hashes it.
	* Input: 
   	*	- unsigned char *str - string to be hashed
    *	- uint32_t length - length of string to be hashed
    * Output: 
	*	- On Success: WORD * - Pointer to digest
	*	- On Failure: NULL
    *****************************************************************************/
    
	PAD_MSG paddedMessageStructure;  //Structure with padded message, length, and block count
    WORD *M;						//Where we will store parsed message
	WORD *digest;					//Where we store the result
	
	paddedMessageStructure = padMessage((unsigned char *)originalMessage, length);
	if(paddedMessageStructure.N==0)
	{
		return NULL;
	}
	
	M = parseMessage(paddedMessageStructure.paddedMessage,paddedMessageStructure.paddedLength,paddedMessageStructure.N);
 	if(M==NULL)
	{
		return NULL;
	}
	free(paddedMessageStructure.paddedMessage); //Clear what we don't need anymore
	
 	digest = calculate(M,paddedMessageStructure.N);
 	if(digest==NULL)
	{
		return NULL;
	}
	free(M);
	
	
	return digest;
}




/*********************************PREPROCESSING********************************/
PAD_MSG padMessage(unsigned char *originalMessage, uint32_t length)
{
	   /******************************************************************************
	    * MSG padMessage(unsigned char *M, uint32_t length)
	    * Description: 
		* 
		* Input: 
	   	* 
	    * Output: 
		*	- On Success: PAD_MSG structure with, pointer to padded string, number of blocks, and length. 
		*	- On Fail:  N will be 0.
	    *****************************************************************************/
	
         uint64_t l = length * 8; // Legnth of message in bits
         uint16_t k = 512 - (l + 1 + 64) % 512; // padding length l+1+k ≡ 448 mod 512
		 uint32_t i;
		 PAD_MSG padMsg;

         //printf( "Length of message in bits(l): %llu\nLength of padding(k): %d\n",l, k);

         uint64_t paddedLength = (l + 1 + k + 64) / 8; //Padded message length in bytes or chars
         //printf("Padded length of message in bits: %llu and in bytes: %llu\n", paddedLength * 8, paddedLength);

         uint64_t lengthOfPadding = (k + 1 + 64) / 8; //Length of all the things we need to add to the message
         unsigned char *padding = (unsigned char *)malloc(lengthOfPadding*sizeof(unsigned char)+1);
         
		 if (padding == NULL)
         {
                  printf("Error with allocating memory \n");
				  padMsg.N=0;
				  return padMsg;
         }
		 
		 
		 /*********************************************
		  * Now we create the padding
		  * 1. Add a 1 right after the message
		  * 2. Fill with 0s
		  * 3. Terminate with the length of the message
		  ********************************************/
         // 1. Add the 1 after the original message
         padding[0] = 0b1 << 7;  

         // 2. Fill the array with 0s which is our padding
         for (i = 1; i < lengthOfPadding - (64 / 8); i++)
         {
         	padding[i] = 0;
         }

         // 3. Last 8 bytes of the padding with length
         padding[i] = (l >> (7 * 8)) & 0xFF;
         padding[++i] = (l >> (6 * 8)) & 0xFF;
         padding[++i] = (l >> (5 * 8)) & 0xFF;
         padding[++i] = (l >> (4 * 8)) & 0xFF;
         padding[++i] = (l >> (3 * 8)) & 0xFF;
         padding[++i] = (l >> (2 * 8)) & 0xFF;
         padding[++i] = (l >> (1 * 8)) & 0xFF;
         padding[++i] = (l >> (0 * 8)) & 0xFF;


         // Create another memory location to fit everything
         unsigned char *paddedMessage = (unsigned char *)malloc(paddedLength*sizeof(unsigned char)+1);
         if (paddedMessage == NULL)
         {
     	 	printf("Error with allocating memory \n");
		  	padMsg.N=0;
		  	return padMsg;
         }
		 
		 // Copy everything into the new space
         memcpy(paddedMessage, originalMessage, length); //First copy the original string
         memcpy((paddedMessage + length ),padding, lengthOfPadding); //Next copy the padding
				
		free(padding); //Don't forget to free up memory we aren't using

   	 	 
         padMsg.paddedMessage = paddedMessage; 
         padMsg.paddedLength = paddedLength;
         padMsg.N = paddedLength / (512/8); //Calculate number of blocks
         return padMsg;
}
WORD * parseMessage(unsigned char *paddedMessage, uint32_t length, uint32_t N)
{
   /******************************************************************************
    * WORD * load_M(WORD *M, unsigned char *msg, uint32_t length, uint32_t N)
    * Description: 
	* 	- Take a byte string and transform it into a 4 byte chucks
	* Input: 
   	*	- unsigned char *paddedMessage
    *	- uint32_t length - length of padded message
	*	- uint32_t N - number of blocks
    * Output: 
	*	- On Success: WORD *M 
	*	- On Failure: NULL
    *****************************************************************************/
    
	WORD * M;
    M = (WORD *)malloc( (N+1) * WORDS_IN_BLOCK * sizeof(WORD)+1);
	if(M==NULL)
	{
		return NULL;
	}
	
    // Load our data into M which consists of N x 512 bit blocks
 	uint32_t j=0;
    for (uint32_t i = 0; i < length; i=i+4)
    {
		*(M+j) = paddedMessage[i+0]<<24|paddedMessage[i+1]<<16|paddedMessage[i+2]<<8|paddedMessage[i+3];
		j++;
    }
 	
	return M;
}

/*********************************ALGORITHM********************************/
WORD *calculate(WORD *M, uint32_t N)
{
   /******************************************************************************
    * WORD *calculate(WORD *M, uint32_t N)
    * Description: 
	* 	- 
	* Input: 
   	*	- 
    *	- 
	*	- 
    * Output: 
	*	- On Success: WORD *M 
	*	- On Failure: NULL
    *****************************************************************************/
    
	uint32_t i;
	WORD W[64]; // Mesasge Schedule
	WORD a, b, c, d, e, f, g, h;		
	WORD T1, T2; // Temporary
	WORD *digest;
	
	digest = calloc(8,sizeof(WORD)); //Allocate 512 bit (64 bytes) for the hash results
	if(digest==NULL)
	{
		return NULL;
	}

	memset(W,0,64*sizeof(WORD));	//Fill W with 0s


	WORD *H0 = (WORD *)malloc(N*sizeof(WORD)+1);
	WORD *H1 = (WORD *)malloc(N*sizeof(WORD)+1);
	WORD *H2 = (WORD *)malloc(N*sizeof(WORD)+1);
	WORD *H3 = (WORD *)malloc(N * sizeof(WORD)+1);
	WORD *H4 = (WORD *)malloc(N * sizeof(WORD)+1);
	WORD *H5 = (WORD *)malloc(N * sizeof(WORD)+1);
	WORD *H6 = (WORD *)malloc(N * sizeof(WORD)+1);
	WORD *H7 = (WORD *)malloc(N * sizeof(WORD)+1);
	if(H0==NULL||H1==NULL||H2==NULL||H3==NULL||H4==NULL||H5==NULL||H6==NULL||H7==NULL)
	{
		return NULL;
	}


	// Load initial Hash values
	H0[0] = H_INIT[0];
	H1[0] = H_INIT[1];
	H2[0] = H_INIT[2];
	H3[0] = H_INIT[3];
	H4[0] = H_INIT[4];
	H5[0] = H_INIT[5];
	H6[0] = H_INIT[6];
	H7[0] = H_INIT[7];

	// printf("H0[0]: %x\n",H0[0]);
	// printf("H1[0]: %x\n",H1[0]);
	// printf("H2[0]: %x\n",H2[0]);
	// printf("H3[0]: %x\n",H3[0]);
	// printf("H4[0]: %x\n",H4[0]);
	// printf("H5[0]: %x\n",H5[0]);
	// printf("H6[0]: %x\n",H6[0]);
	// printf("H7[0]: %x\n",H7[0]);
										 
	 //puts("Loaded initial hash values");
	for (i = 1; i <= N; i++)
	{
		
		#ifdef __SHA256_DBG
		printf("i\tt\tW[t]\tSIG1(W[t-2])\tW[t-7]\tSIG0(W[t-15])\tW[t-16]\n");
		#endif             
     	
		//Step 1. Load W 
		for (uint32_t t = 0; t <= 63; t++)
		{
			if (t <= 15) //Load W with the message
			{
				W[t] = (M[t+(i-1)*WORDS_IN_BLOCK]);

				#ifdef __SHA256_DBG
				printf("%d\t%d\t%08x\n",i, t, W[t]);
				#endif
			}
			else
			{
				W[t] = SIG1(W[t - 2]) + W[t - 7] + SIG0(W[t - 15]) + W[t - 16];
				#ifdef __SHA256_DBG
				printf("%d\t%d\t%08x\t%08x\t%08x\t%08x\t%08x\n",i,  t, W[t],  SIG1(W[t-2]),W[t-7],SIG0(W[t-15]),W[t-16]);
				#endif		
			}
		}
		           
		// Step 2. Load working variables a-h
		a = H0[i - 1];
		b = H1[i - 1];
		c = H2[i - 1];
		d = H3[i - 1];
		e = H4[i - 1];
		f = H5[i - 1];
		g = H6[i - 1];
		h = H7[i - 1];
				  
		// Step 3. Calculate T1, T2, a-h, and iterate 64 times
		for (uint32_t t = 0; t <= 63; t++)
		{
				   
			T1 = h + SUM1(e) + CH(e, f, g) + K[t] + W[t];
			T2 = SUM0(a) + MAJ(a, b, c);

			#ifdef _SHA256_DBG
			printf("T1: %x, h: %x, SUM1(e): %x, CH(e,f,g): %x, K[t]: %x, W[t]: %x\n", T1, h, SUM1(e), CH(e, f, g), K[t],  W[t]);
			#endif			   
			
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
			
			#ifdef _SHA256_DBG
			printf("t = %d : %08x %08x %08x %08x %08x %08x %08x %08x\n",t, a,b,c,d,e,f,g,h);
			#endif
		}

			H0[i] = a + H0[i - 1];
			H1[i] = b + H1[i - 1];
			H2[i] = c + H2[i - 1];
			H3[i] = d + H3[i - 1];
			H4[i] = e + H4[i - 1];
			H5[i] = f + H5[i - 1];
			H6[i] = g + H6[i - 1];
			H7[i] = h + H7[i - 1];

	}
	
	//Load the result and return	 
	digest[0]=H0[N];
	digest[1]=H1[N];
	digest[2]=H2[N];
	digest[3]=H3[N];
	digest[4]=H4[N];
	digest[5]=H5[N];
	digest[6]=H6[N];
	digest[7]=H7[N];

	return digest;
}
void print_H(WORD *H)
{
   /******************************************************************************
    * void print_H(WORD *H)
    * Input: 
   	* WORD *H - Hash to be printed
    * Output: None
    *****************************************************************************/
	for (uint32_t i=0;i<WORDS_IN_HASH;i++)
	{
		printf("%08x ",H[i]);
	}
	printf("\n");
}