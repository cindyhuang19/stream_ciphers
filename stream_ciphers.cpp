#include <iostream>
#include <cmath>

#ifndef MARMOSET_TESTING
int main();
#endif

char *encode(char *plaintext, unsigned long key);
char *decode(char *ciphertext, unsigned long key);

#ifndef MARMOSET_TESTING
int main() {
	long key = 0;
	char str[] = {"HI"};
	char *ciphertext = {encode(str, key)};
	std::cout << ciphertext << std::endl;
	char *plaintext = {decode(ciphertext, key)};
	std::cout << plaintext << std::endl;
	return 0;
}
#endif

char *encode(char *plaintext, unsigned long key) {

	// creates state array
	unsigned char *state_array = new unsigned char [256];

	// assigns state array entries values of 0 through 255
	for (std::size_t n = 0; n < 256; n++) {
		state_array[n] = n;
	}

	// converts encryption key from long to binary array
	unsigned int *key_array = new unsigned int [64];

	for (std::size_t n = 64; n > 0; n--) {
		if ((key - (std::pow(2, (n-1)))) >= 0) {
			key = key - std::pow(2, (n-1));
			key_array[n - 1] = 1;
		}
		else {
			key_array[n - 1] = 0;
		}
	}

	// scrambles state array
	unsigned int i = 0;
	unsigned int j = 0;

	for (unsigned int n = 0; n < 256; n++) {
		unsigned int k = (i % 64);
		j = (j + state_array[i] + key_array[k]) % 256;
		unsigned char temp = state_array[i];
		state_array[i] = state_array[j];
		state_array[j] = temp;
		i = (i+1) % 256;
	}

	// counts number of characters in plaintext
	int char_count = 0;
	int p = 0;

	while (plaintext[p] != '\0') {
		if (plaintext[p] != '\0') {
			char_count++;
		}
		p++;
	}

	// increases number of characters in plain text to a multiple of four
	int extra_char_count = 0;
	if ((char_count % 4) != 0) {
		while (((char_count + extra_char_count) % 4) != 0){
			extra_char_count++;
		}
	}

	// adds number of null characters necessary to make plain text length a multiple of four
	int size = char_count + extra_char_count;
	unsigned char *newplaintext = new unsigned char [size];
	for (std::size_t b = 0; b < size; b++) {
		if (b < char_count) {
			newplaintext[b] = plaintext[b];
		}
		else {
			newplaintext[b] = '\0';
		}
	}

	// scrambles plaintext array
	unsigned char temp2 = '\0';
	unsigned char r = '\0';
	unsigned char R = '\0';

	for (std::size_t q = 0; q < size; q++) {
		i = ((i + 1) % 256);
		j = ((j + state_array[i]) % 256);
		temp2 = state_array[i];
		state_array[i] = state_array[j];
		state_array[j] = temp2;
		r = ((state_array[i] + state_array[j]) % 256);
		R = state_array[r];
		newplaintext[q] = newplaintext[q] ^ R;
	}

	// ascii armour
	unsigned int dec_val = 0;
	char *decomposed_array = new char [(size/4)*5];
	unsigned int quotient = 0;
	unsigned int mask = 1;

	for (std::size_t h = 0; h < (size/4); h++) {
		dec_val = 0;
		bool bin_val[32] = {0};
		// determines binary representation for each byte
		for (std::size_t n = 0; n < 4; n++) {
				mask = 1;
			for (std::size_t e = 0; e < 8; e++) {
				if (newplaintext[(h*4) + n] & mask) {
					bin_val[((n+1)*8) - 1 - e] = 1;
				}
				else {
					bin_val[((n+1)*8) - 1 - e] = 0;
				}
				mask = mask << 1;
			}
		}
		// determines decimal value for chunk of four characters
		for (std::size_t r = 32; r > 0; r--) {
			if (bin_val[r-1] == 1) {
				dec_val += std::pow(2, (32 - r));
			}
		}
		// assigns values for decomposed array
		for (std::size_t g = 0; g < 5; g++) {
			quotient = dec_val/(std::pow(85, (4 - g)));
			if (quotient > 0) {
				dec_val = dec_val - (quotient*(std::pow(85, (4-g))));
			}
			decomposed_array[(h*5) + g] = quotient + 33;
		}
	}
	decomposed_array[(size/4)*5] = '\0';
	return decomposed_array;
}


char *decode(char *ciphertext, unsigned long key) {
	// counts number of characters in ciphertext
	unsigned int char_count = 0;

	while (ciphertext[char_count] != '\0') {
			char_count++;
	}

	// ascii armour
	unsigned int four_byte_blocks = (char_count/5);
	unsigned int dec_val = 0;
	unsigned int *bin_val = new unsigned int[32];
	unsigned int mask = 1;
	unsigned char *ascii_val = new unsigned char [four_byte_blocks*4];
	unsigned int bin_num = 0;

	for (std::size_t t = 0; t < four_byte_blocks; t++) {
		dec_val = 0;
		// determines decimal value for chunk of five characters
		for (std::size_t u = 0; u < 5; u++) {
			ciphertext[(t*5) + u] -= 33;
			dec_val = dec_val + (ciphertext[(t*5) + u] * std::pow(85, (4 - u)));
		}
		mask = 1;
		// converts decimal number to value stored in binary array
		for (std::size_t e = 0; e < 32; e++) {
			if (dec_val & mask) {
				bin_val[31 - e] = 1;
			}
			else {
				bin_val[31 - e] = 0;
			}
			mask = mask << 1;
		}
		// converts binary values to ascii characters
		for (std::size_t u = 0; u < 4; u++) {
			bin_num = 0;
			for (std::size_t v = 0; v < 8; v++) {
				bin_num += bin_val[v+ (u*8)] * std::pow(2,(7-v));
			}
			ascii_val[u + (t*4)] = bin_num;
		}
	}

	// counts number of characters in ascii_val
	unsigned int ascii_count = four_byte_blocks*4;

	// creates state array of null characters
	unsigned char state_array[256] = {'\0'};

	// assigns state array entries values of 0 through 255
	for (std::size_t n = 0; n < 256; n++) {
		state_array[n] = n;
	}

	// converts encryption key from long to binary array
	unsigned int key_array[64] = {0};
	for (std::size_t n = 64; n > 0; n--) {
		if ((key - (std::pow(2, (n-1)))) >= 0) {
			key = key - std::pow(2, (n-1));
			key_array[n - 1] = 1;
		}
		else {
			key_array[n - 1] = 0;
		}
	}

	// scrambles state array
	int i = 0;
	int j = 0;
	int k = 0;
	unsigned char temp = '\0';

	for (std::size_t m = 0; m < 256; m++) {
		k = i % 64;
		j = ((j + state_array[i] + key_array[k]) % 256);
		temp = state_array[i];
		state_array[i] = state_array[j];
		state_array[j] = temp;
		i = ((i+1) % 256);
	}

	// scrambles ascii array to find decoded array
	unsigned char temp2 = '\0';
	unsigned char r = '\0';
	unsigned char R = '\0';
	char *decoded_array = new char [ascii_count];

	for (std::size_t q = 0; q < ascii_count; q++) {
		i = ((i + 1) % 256);
		j = ((j + state_array[i]) % 256);
		temp2 = state_array[i];
		state_array[i] = state_array[j];
		state_array[j] = temp2;
		r = ((state_array[i] + state_array[j]) % 256);
		R = state_array[r];
		decoded_array[q] = ascii_val[q] ^ R;
	}

	return decoded_array;
}


