#pragma once
#pragma once
#ifndef _CALTOY_H_
#define _CALTOY_H_


#ifdef __cplusplus
extern "C" {
#endif


#ifndef NOCRYPT
#define NOCRYPT
#endif

#ifndef DLL_DEVELOPEMENT
#define DLL_DEFINE __declspec(dllimport)
#else
#define DLL_DEFINE __declspec(dllexport)
#endif

#include <stdint.h>
#include <stdio.h>
	typedef uint32_t pt_t; //plaintext type
	typedef uint32_t ct_t; //ciphertext type
	typedef uint32_t st_t; //intermedeate type
	typedef uint32_t rk_t; //roundkey type
	typedef uint8_t  wd_t; //word type

	/*
		void caltoy_perm(st_t * out, st_t in) : Permutation Layer, in�� 16��Ʈ ���� �Է��ϸ� 16��Ʈ out�� ���
		void caltoy_inv_perm(st_t * out, st_t in) : Inverse Permutation Layer
		void caltoy_sub(st_t * out, st_t in) : Substitution Layer, in�� 16��Ʈ ���� �Է��ϸ� 16��Ʈ out�� ���
		void caltoy_inv_sub(st_t * out, st_t in) : Inverse Substitution Layer
		void caltoy_round(st_t * out, st_t in, rk_t rk) : "Substitution Layer + Permutation Layer + Key XOR",
														  in�� 16��Ʈ ���� �Է�, rk�� 16��Ʈ Ű ���� �Է��ϸ� 16��Ʈ out�� ���
		void caltoy_inv_round(st_t * out, st_t in, rk_t rk) : "Key XOR + Inverse Permutation Layer + Inverse Substition Layer"
		void caltoy_enc(ct_t * out, pt_t in) : in�� 16��Ʈ ���� �Է��ϸ� �ش� ���� ��ȣȭ ��Ų 16��Ʈ out�� ���
		extern wd_t caltoy_sbox[16] : Sbox�� Ȯ���� �� ����
		extern wd_t caltoy_inv_sbox[16] : Inverse Sbox�� Ȯ���� �� ����
	*/

	DLL_DEFINE void caltoy_perm(st_t * out, st_t in);
	DLL_DEFINE void caltoy_inv_perm(st_t * out, st_t in);
	DLL_DEFINE void caltoy_sub(st_t * out, st_t in);
	DLL_DEFINE void caltoy_inv_sub(st_t * out, st_t in);
	DLL_DEFINE void caltoy_round(st_t * out, st_t in, rk_t rk);
	DLL_DEFINE void caltoy_inv_round(st_t * out, st_t in, rk_t rk);
	DLL_DEFINE void caltoy_enc(ct_t * out, pt_t in);
	DLL_DEFINE void caltoy_text_print(char * added_str, st_t text);
	DLL_DEFINE extern wd_t caltoy_sbox[16];
	DLL_DEFINE extern wd_t caltoy_inv_sbox[16];

#ifdef __cplusplus
}
#endif //extern "C"

#endif