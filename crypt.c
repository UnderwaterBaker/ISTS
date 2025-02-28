#include <Windows.h>

typedef struct
{
        unsigned int i;
        unsigned int j;
        unsigned char s[256];

} Rc4Context;

void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL)
		return;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		j = (j + context->s[i] + key[i % length]) % 256;

		//Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}
void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// Valid input and output?
		if (input != NULL && output != NULL)
		{
			//XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			//Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
}
void RC4Crypt(unsigned char* key, unsigned char* input, unsigned char* output, size_t size)
{
	//	size_t inputSize = sizeof(input);
	Rc4Context ctx = { 0 };
	rc4Init(&ctx, key, sizeof(key));

	//unsigned char* Ciphertext = (unsigned char*)malloc(inputSize);
	ZeroMemory(output, size);
	rc4Cipher(&ctx, input, output, size);
}

#define SHELLCODE_SIZE 276
//#define KEY2 "secondKey"
//#define KEY1 "47329wewawawa^&%%81bfdsamfda"
int main(int arc, char* argv[])
{
        extern unsigned char shellcode[SHELLCODE_SIZE];
        unsigned char cryptRound2[SHELLCODE_SIZE];

/*
	printf("\n[+] DECRYPT ROUND 2 : %s \n", argv[1]);
	RC4Crypt(argv[1], shellcode, cryptRound2, SHELLCODE_SIZE);
	printf("\n[+] DECRYPT ROUND 1: %s \n", argv[2]);
*/
	RC4Crypt(argv[2], shellcode, cryptRound2, SHELLCODE_SIZE);
	printf("unsigned char shellcode[] = \"");
	RC4Crypt(argv[1], cryptRound2, shellcode, SHELLCODE_SIZE);
	for (int i = 0; i < SHELLCODE_SIZE; i++)
	{
		printf("\\x%x", shellcode[i]);
	}
	printf("\";\n");
}
