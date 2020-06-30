/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <hmac_ta.h>

/* generated with scripts/digest_hmac.pl */
static const uint8_t mac_data_sha1_key1[10] = {
	0x6B, 0x65, 0x79, 0x6B, 0x65, 0x79, 0x6B, 0x65, 0x79, 0x6B /* keykeykeyk */
};

static const uint8_t mac_data_sha1_in1[] = {
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, /* The quic */
	0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20, /* k brown  */
	0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, /* fox jump */
	0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x74, /* s over t */
	0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, /* he lazy  */
	0x64, 0x6F, 0x67,                               /* dog */
};

//static const uint8_t mac_data_sha1_out1[] = {
//	0xDE, 0x7C, 0x9B, 0x85, 0xB8, 0xB7, 0x8A, 0xA6, /* .|...... */
//	0xBC, 0x8A, 0x7A, 0x36, 0xF7, 0x0A, 0x90, 0x70, /* ..z6...p */
//	0x1C, 0x9D, 0xB4, 0xD9,                         /* .... */
//};

static const uint8_t mac_data_sha1_out1[] = {
	0xE4, 0x2E, 0x20, 0x42, 0x73, 0xDE, 0x8A, 0xFC,
	0x9E, 0x19, 0x80, 0x5B, 0x8A, 0xC4, 0xBA, 0xFC,
	0xFB, 0x51, 0x85, 0x86
};

int main(void)
{
	TEEC_Context ctx;
	TEEC_Operation op = { 0 };
	TEEC_Result res;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_HMAC_UUID;

	size_t i;
	uint32_t err_origin;
	uint32_t hmac_value;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, err_origin);

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
 					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
 	op.params[0].tmpref.buffer = mac_data_sha1_key1;
 	op.params[0].tmpref.size = sizeof(mac_data_sha1_key1);

 	fprintf(stdout, "Register the shared key: %s\n", mac_data_sha1_key1);
 	res = TEEC_InvokeCommand(&sess, TA_HMAC_CMD_REGISTER_SHARED_KEY,
 				 &op, &err_origin);
 	if (res != TEEC_SUCCESS) {
 		fprintf(stderr, "TEEC_InvokeCommand failed with code 0x%x "
 			"origin 0x%x\n",
 			res, err_origin);
 		goto exit;
 	}

	/* 2. Register the message */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
 					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
 	op.params[0].tmpref.buffer = mac_data_sha1_in1;
 	op.params[0].tmpref.size = sizeof(mac_data_sha1_in1);

 	fprintf(stdout, "Register the message: %s\n", mac_data_sha1_in1);
 	res = TEEC_InvokeCommand(&sess, TA_HMAC_CMD_REGISTER_MESSAGE,
 				 &op, &err_origin);
 	if (res != TEEC_SUCCESS) {
 		fprintf(stderr, "TEEC_InvokeCommand failed with code 0x%x "
 			"origin 0x%x\n",
 			res, err_origin);
 		goto exit;
 	}

	/* 3. Register the output */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
 					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
 	op.params[0].tmpref.buffer = mac_data_sha1_out1;
 	op.params[0].tmpref.size = sizeof(mac_data_sha1_out1);

 	fprintf(stdout, "Register the output: %s\n", mac_data_sha1_out1);
 	res = TEEC_InvokeCommand(&sess, TA_HMAC_CMD_REGISTER_OUTPUT,
 				 &op, &err_origin);
 	if (res != TEEC_SUCCESS) {
 		fprintf(stderr, "TEEC_InvokeCommand failed with code 0x%x "
 			"origin 0x%x\n",
 			res, err_origin);
 		goto exit;
 	}

	/* 2. Get HMAC based One Time Passwords */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(&sess, TA_HMAC_CMD_GET_HMAC, &op,
					 &err_origin);
  if (res != TEEC_SUCCESS) {
			fprintf(stderr, "TEEC_InvokeCommand failed with code "
				"0x%x origin 0x%x\n", res, err_origin);
			goto exit;
	}
	hmac_value = op.params[0].value.a;
  fprintf(stdout, "HMAC: %d\n", hmac_value);

	return 0;
}
