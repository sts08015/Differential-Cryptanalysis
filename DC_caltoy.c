#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "DC_caltoy.h"
#define SZ  131072  //1<<17
typedef struct
{
	pt_t p1;
	pt_t p2;
}plain_pair;  // �򹮽���ǥ���ѱ���ü�̴�.
typedef struct { ct_t c1;  ct_t c2; }cipher_pair; // ��ȣ������ǥ���ѱ���ü�̴�.
wd_t dc_table[16][16];  // dc table�������ϴ¹迭�̴�.
plain_pair plain[SZ]; // �������������ϴ� random�� 2byte plaintext pair�������ϴ¹迭�̴�.
cipher_pair cipher[SZ]; // plain�����Ѿ�ȣ�����������ϴ¹迭�̴�.
char chk[SZ]; // ��ȣ����, ��ȣ�������������ϴ� index��ǥ���ϴ¹迭�̴�.
char check_key[16][SZ]; // filtering������Ѿ�ȣ����, sbox������������������������� sbox���Է������������ϴ°�츦ǥ���ϴ��������迭�̴�. �Ұ����Ѿ�ȣ�� : -1, ��������������Ư���ĸ��� x : 0, ����Ư���ĸ��� o ;
char real_key[16];  // ������Ư���Ŀ����ؼ����ɼ��̳��� key����Ǵ��̵Ǹ�, 1�������ش�. ��, Ű���ٰ��ɼ��̳���Ű�μ��õ�ȸ���������ϴ¹迭�̴�.
void create_dc_table(); // caltoy_sbox[16]���������� DC_table�������ϴ��Լ��̴�.
void generate_plaintext_pair(int diff); // �����������������ϴ� plaintext ���������ϴ��Լ��̴�.
void generate_ciphertext_pair();  // �������򹮽ֿ��ش��ϴ¾�ȣ�����������ϴ��Լ��̴�.
void check_cipher();  // ��ȣ�����߾�ȣ�����������������ϴ½����˻��ϴ��Լ��̴�.
void guess_key(int val);  // 4bit key�� guess�ϰ�κк�ȣȭ���������Ŀ�, sbox���������������, check_key �迭��ä���ش�.
void clear(); // �ʱ�ȭ���ʿ��ѹ迭�����ʱ�ȭ���ִ��Լ��̴�.
void print_realkey(); // ���км��������ϰ�˰Ե� key������ϴ��Լ��̴�. �̴� real_key�迭�����ִ��������� index������Ѵ�.
int main(void) { int input_diff[] = { 0xA000 };  int val[] = { 12 };  int i;  srand(time(NULL));  create_dc_table();  for (i = 0; i < sizeof(input_diff) / sizeof(int); i++) { clear();    generate_plaintext_pair(input_diff[i]);    generate_ciphertext_pair();    check_cipher();    guess_key(val[i]); }  print_realkey();  return 0; }
void create_dc_table() {
	wd_t i, j;  for (i = 0; i < 16; i++) {
		for (j = 0; j < 16; j++) {
			wd_t input_diff = i ^ j;  // �Է����а��      
			wd_t output_diff = caltoy_sbox[i] ^ caltoy_sbox[j]; // ������а��      
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
		plain[i].p2 = plain[i].p1 ^ diff; // �������������ϴ·����ѵ��򹮽ֻ���  
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
			if (chk[j] != 1) check_key[i][j] = -1;  // �Ұ����Ѱ��� -1���ʱ�ȭ      
			else {
				ct_t O1 = (((cipher[j].c1 & 0x0f00) >> 8) ^ i); // guess�ϴ� key�ͺκ� xor        
				ct_t O2 = (((cipher[j].c2 & 0x0f00) >> 8) ^ i);
				ct_t I1 = caltoy_inv_sbox[O1];  // sbox�������δ���        
				ct_t I2 = caltoy_inv_sbox[O2];
				if ((ct_t)(I1 ^ I2) == val) // ����Ư�����������ϴ°��        
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
