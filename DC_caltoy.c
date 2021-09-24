#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "DC_caltoy.h"
#define SZ  131072  //1<<17
typedef struct
{
	pt_t p1;
	pt_t p2;
}plain_pair;  // 평문쌍을표현한구조체이다.
typedef struct { ct_t c1;  ct_t c2; }cipher_pair; // 암호문쌍을표현한구조체이다.
wd_t dc_table[16][16];  // dc table을저장하는배열이다.
plain_pair plain[SZ]; // 평문차분을만족하는 random한 2byte plaintext pair를저장하는배열이다.
cipher_pair cipher[SZ]; // plain에대한암호문쌍을저장하는배열이다.
char chk[SZ]; // 암호문중, 암호문차분을만족하는 index를표시하는배열이다.
char check_key[16][SZ]; // filtering을통과한암호문중, sbox를역으로통과했을때도마지막 sbox의입력차분을만족하는경우를표시하는이차원배열이다. 불가능한암호문 : -1, 가능하지만차분특성식만족 x : 0, 차분특성식만족 o ;
char real_key[16];  // 각차분특성식에대해서가능성이높은 key라고판단이되면, 1을더해준다. 즉, 키마다가능성이높은키로선택된회수를저장하는배열이다.
void create_dc_table(); // caltoy_sbox[16]를기준으로 DC_table을생성하는함수이다.
void generate_plaintext_pair(int diff); // 평문차분조건을만족하는 plaintext 쌍을생성하는함수이다.
void generate_ciphertext_pair();  // 생성한평문쌍에해당하는암호문쌍을생성하는함수이다.
void check_cipher();  // 암호문쌍중암호문차분조건을만족하는쌍을검사하는함수이다.
void guess_key(int val);  // 4bit key를 guess하고부분복호화를진행한후에, sbox를역으로통과시켜, check_key 배열을채워준다.
void clear(); // 초기화가필요한배열들을초기화해주는함수이다.
void print_realkey(); // 차분분석을진행하고알게된 key를출력하는함수이다. 이는 real_key배열에서최댓값을가지는 index를출력한다.
int main(void) { int input_diff[] = { 0xA000 };  int val[] = { 12 };  int i;  srand(time(NULL));  create_dc_table();  for (i = 0; i < sizeof(input_diff) / sizeof(int); i++) { clear();    generate_plaintext_pair(input_diff[i]);    generate_ciphertext_pair();    check_cipher();    guess_key(val[i]); }  print_realkey();  return 0; }
void create_dc_table() {
	wd_t i, j;  for (i = 0; i < 16; i++) {
		for (j = 0; j < 16; j++) {
			wd_t input_diff = i ^ j;  // 입력차분계산      
			wd_t output_diff = caltoy_sbox[i] ^ caltoy_sbox[j]; // 출력차분계산      
			dc_table[input_diff][output_diff]++;
		}
	}
	for (i = 0; i < 16; i++)
	{
		for (j = 0; j < 16; j++)
		{
			printf("%2d", dc_table[i][j]);
		}    printf("\n");
	}
}void generate_plaintext_pair(int diff) {
	int i;  const int MAX = 0x10;  for (i = 0; i < SZ; i++) {
		unsigned char nibble1 = rand() % MAX;
		unsigned char nibble2 = rand() % MAX;
		unsigned char nibble3 = rand() % MAX;
		unsigned char nibble4 = rand() % MAX;
		plain[i].p1 = (nibble1 << 12) | (nibble2 << 8) | (nibble3 << 4) | (nibble4);
		plain[i].p2 = plain[i].p1 ^ diff; // 평문차분을만족하는랜덤한두평문쌍생성  
	}
}
void generate_ciphertext_pair() {
	int i;
	for (i = 0; i < SZ; i++) {
		caltoy_enc(&(cipher[i].c1), plain[i].p1);    caltoy_enc(&(cipher[i].c2), plain[i].p2);
	}
}void check_cipher() {
	int i;  int cnt = 0;  for (i = 0; i < SZ; i++) {
		int x = (cipher[i].c1 ^ cipher[i].c2);
		if ((x & 1) == 0 && ((x >> 1) & 1) == 0 && ((x >> 3) & 1))  //0?00    
		{
			chk[i] = 1;
			cnt++;
		}
	}
	//printf("\n%d %#x\n", cnt,cnt);
}void guess_key(int val) {
	int i, j;  int count[16] = { 0 };
	for (i = 0; i < 0xF; i++) // key 
	{
		for (j = 0; j < SZ; j++)
		{
			if (chk[j] != 1) check_key[i][j] = -1;  // 불가능한경우는 -1로초기화      
			else {
				ct_t O1 = (((cipher[j].c1 & 0x0f00) >> 8) ^ i); // guess하는 key와부분 xor        
				ct_t O2 = (((cipher[j].c2 & 0x0f00) >> 8) ^ i);
				ct_t I1 = caltoy_inv_sbox[O1];  // sbox를역으로대입        
				ct_t I2 = caltoy_inv_sbox[O2];
				if ((ct_t)(I1 ^ I2) == val) // 차분특성식을만족하는경우        
				{
					check_key[i][j] = 1;
				}
				//printf("%2d", check_key[i][j]);      
			}
		}
		//puts("");  
	}  for (i = 0; i < 16; i++)
	{
		for (j = 0; j < SZ; j++) { if (check_key[i][j] == 1) count[i]++; }
	}
	//puts("\n\n");  
	int mx = -1;  for (i = 0; i < 16; i++) {
		if (mx < count[i]) { mx = count[i]; }
		//printf("%4d ", count[i]);  
	}
	for (i = 0; i < 16; i++)
	{
		if (mx == count[i]) real_key[i] ++;
	}
}
void clear() {
	int i, j;
	for (i = 0; i < 16; i++)
	{
		for (j = 0; j < SZ; j++)
		{
			check_key[i][j] = 0;
		}
	}
	for (i = 0; i < SZ; i++) {
		chk[i] = 0;
		plain[i].p1 = 0;
		plain[i].p2 = 0; cipher[i].c1 = 0;    cipher[i].c2 = 0;
	}
}void print_realkey() {
	int mx = -1, mxIdx = 0, i;
	for (i = 0; i < 16; i++)
	{
		if (mx < real_key[i])mx = real_key[i];
	}
	puts("\nK6's 4,5,6,7nd partial key");
	for (i = 0; i < 16; i++) {
		//printf("%d ", real_key[i]);   
		if (mx == real_key[i]) printf("%d\n", i);
	}
}
