/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <hmac_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

/* The size of a SHA1 hash in bytes. */
#define SHA1_HASH_SIZE 20

/* GP says that for HMAC SHA-1, max is 512 bits and min 80 bits. */
#define MAX_KEY_SIZE 64 /* In bytes */
#define MIN_KEY_SIZE 10 /* In bytes */
#define MAX_MESSAGE_SIZE 64 /* In bytes */
#define MIN_MESSAGE_SIZE 64 /* In bytes */

/* Dynamic Binary Code 2 Modulo, which is 10^6 according to the spec. */
#define DBC2_MODULO 1000000

/*
 * Currently this only supports a single key, in the future this could be
 * updated to support multiple users, all with different unique keys (stored
 * using secure storage).
 */
static uint8_t K[MAX_KEY_SIZE];
static uint32_t K_len;

/* The input message. */
static uint8_t input[MAX_MESSAGE_SIZE];
static uint32_t input_len;

/* The input message. */
static uint8_t output[SHA1_HASH_SIZE];
static uint32_t output_len;

/*
 *  HMAC a block of memory to produce the authentication tag
 *  @param key       The secret key
 *  @param keylen    The length of the secret key (bytes)
 *  @param in        The data to HMAC
 *  @param inlen     The length of the data to HMAC (bytes)
 *  @param out       [out] Destination of the authentication tag
 *  @param outlen    [in/out] Max size and resulting size of authentication tag
 */
 static TEE_Result hmac_sha1(const uint8_t *key, const size_t keylen,
			    const uint8_t *in, const size_t inlen,
			    uint8_t *out, uint32_t *outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	if (keylen < MIN_KEY_SIZE || keylen > MAX_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!in || !out || !outlen)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * 1. Allocate cryptographic (operation) handle for the HMAC operation.
	 *    Note that the expected size here is in bits (and therefore times
	 *    8)!
	 */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA1, TEE_MODE_MAC,
				    keylen * 8);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 2. Allocate a container (key handle) for the HMAC attributes. Note
	 *    that the expected size here is in bits (and therefore times 8)!
	 */
	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, keylen * 8,
					  &key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 3. Initialize the attributes, i.e., point to the actual HMAC key.
	 *    Here, the expected size is in bytes and not bits as above!
	 */
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	/* 4. Populate/assign the attributes with the key object */
	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/* 5. Associate the key (object) with the operation */
	res = TEE_SetOperationKey(op_handle, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/* 6. Do the HMAC operations */
	TEE_MACInit(op_handle, NULL, 0);
	TEE_MACUpdate(op_handle, in, inlen);
	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, outlen);
exit:
	if (op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(op_handle);

	/* It is OK to call this when key_handle is TEE_HANDLE_NULL */
	TEE_FreeTransientObject(key_handle);

	return res;
}

 static TEE_Result register_shared_key(uint32_t param_types, TEE_Param params[4])
 {
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size > sizeof(K))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(K, 0, sizeof(K));
	memcpy(K, params[0].memref.buffer, params[0].memref.size);

	K_len = params[0].memref.size;
	DMSG("Got shared key %s (%u bytes).", K, params[0].memref.size);

	return res;

 }

 static TEE_Result register_message(uint32_t param_types, TEE_Param params[4])
 {
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size > sizeof(input))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(input, 0, sizeof(input));
	memcpy(input, params[0].memref.buffer, params[0].memref.size);

	input_len = params[0].memref.size;
	DMSG("Got message %s (%u bytes).", input, params[0].memref.size);

	return res;

 }

 static TEE_Result register_output(uint32_t param_types, TEE_Param params[4])
 {
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size > sizeof(output))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(output, 0, sizeof(output));
	memcpy(output, params[0].memref.buffer, params[0].memref.size);

	output_len = params[0].memref.size;
	DMSG("Got output %s (%u bytes).", output, params[0].memref.size);

	return res;

 }

 static TEE_Result get_hmac(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t mac[SHA1_HASH_SIZE];
	uint32_t mac_len = sizeof(mac);
	uint32_t i;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = hmac_sha1(K, K_len, input, input_len, mac, &mac_len);
	params[0].value.a = 0;

	for (i = 0; i < output_len; i++)
	{
		if (mac[i] != output[i]) {
			params[0].value.a = 1;
			break;
		}
	}
	return res;
}
/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
		case TA_HMAC_CMD_REGISTER_SHARED_KEY:
			return register_shared_key(param_types, params);

		case TA_HMAC_CMD_REGISTER_MESSAGE:
			return register_message(param_types, params);

		case TA_HMAC_CMD_REGISTER_OUTPUT:
			return register_output(param_types, params);

		case TA_HMAC_CMD_GET_HMAC:
			return get_hmac(param_types, params);

		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}
