#include <php.h>
#include <zend_string.h>
#include <zend_exceptions.h>
#include <zend_types.h>
#include <zend_operators.h>
#include <stdlib.h>
#include <ext/standard/base64.h>
#include <stdio.h>
#include <memory.h>
#include "compiler.h"
#include "aes.h"
#include "config.h"
#include "pkcs7.h"



ZEND_DECLARE_MODULE_GLOBALS(easy_compiler);

PHP_MINIT_FUNCTION(easy_compiler)
{
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(easy_compiler)
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION(easy_compiler)
{
     php_info_print_table_start();
     php_info_print_table_header(2, "Version", PHP_EASY_COMPILER_VERSION);
     php_info_print_table_header(2, "Author", "如果的如果");
     php_info_print_table_header(2, "Email", "admin@fosuss.com");
     php_info_print_table_end();
     DISPLAY_INI_ENTRIES();
}

zend_function_entry easy_compiler_functions[] = {
        PHP_FE(easy_compiler_encrypt, NULL)
        PHP_FE(easy_compiler_decrypt, NULL)
        PHP_FE(easy_compiler_eval, NULL)
        PHP_FE_END
};

zend_module_entry easy_compiler_module_entry = {
        STANDARD_MODULE_HEADER,
        PHP_EASY_COMPILER_EXTNAME,
        easy_compiler_functions,
        PHP_MINIT(easy_compiler),
        PHP_MSHUTDOWN(easy_compiler),
        NULL,
        NULL,
        PHP_MINFO(easy_compiler),
        PHP_EASY_COMPILER_VERSION,
        STANDARD_MODULE_PROPERTIES,
};

ZEND_GET_MODULE(easy_compiler);

PHP_FUNCTION(easy_compiler_encrypt) {
    unsigned char *raw_string;
    size_t *raw_string_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &raw_string, &raw_string_len) == FAILURE) {
        RETURN_NULL();
    }
    unsigned char *pkcs7 = (unsigned char *)malloc(sizeof(unsigned char*)*PKCS7_MAX_LEN);
    memcpy(pkcs7,raw_string,raw_string_len);
    size_t after_padding_len = PKCS7Padding(pkcs7,raw_string_len);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV_KEY);
    AES_CBC_encrypt_buffer(&ctx,pkcs7,after_padding_len);
    zend_string *zend_encode_string = zend_string_init(pkcs7,after_padding_len,0);
    zend_string *base64;
    base64 = php_base64_encode((const unsigned char*)ZSTR_VAL(zend_encode_string),ZSTR_LEN(zend_encode_string));
    char *res = ZSTR_VAL(base64);
    zend_string_release(base64);
    zend_string_release(zend_encode_string);
    free(pkcs7);
    RETURN_STRING(res);
};

PHP_FUNCTION(easy_compiler_decrypt) {
    unsigned char *base64;
    size_t *base64_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &base64, &base64_len) == FAILURE) {
        RETURN_NULL();
    }
    zend_string *encrypt_z_str;
    encrypt_z_str = php_base64_decode(base64,base64_len);
    size_t encrypt_len = NULL;
    encrypt_len = ZSTR_LEN(encrypt_z_str);
    unsigned char *pkcs7 = (unsigned char *)malloc(sizeof(unsigned char*)*PKCS7_MAX_LEN);
    memcpy(pkcs7,(const char*)ZSTR_VAL(encrypt_z_str),encrypt_len);
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, AES_IV_KEY);
    AES_CBC_decrypt_buffer(&ctx,pkcs7,encrypt_len);
    encrypt_len = PKCS7Cutting(pkcs7,encrypt_len);
    zend_string *eval_string = zend_string_init(pkcs7,encrypt_len,0);
    char *res= ZSTR_VAL(eval_string);
    int i;
    for (i = encrypt_len - 1; i >= 0; i--) {
        if (res[i] == 16) {
            res[i] = '\0';
            encrypt_len--;
        } else {
            break;
        }
    }
    zend_string *eval_string2 = zend_string_init(res,encrypt_len,0);
    zval z_str;
    ZVAL_STR(&z_str,eval_string2);
    zend_op_array *new_op_array;
    char *filename = zend_get_executed_filename();
    new_op_array =  easy_compiler_compile_string(&z_str, filename);
    if(new_op_array){
        zend_try {
            zend_execute(new_op_array,return_value);
        } zend_catch {

        } zend_end_try();
        destroy_op_array(new_op_array);
        efree(new_op_array);
    }
    zend_string_release(encrypt_z_str);
    zend_string_release(eval_string);
    free(pkcs7);
};


PHP_FUNCTION(easy_compiler_eval){
    unsigned char *raw_string;
    //base64参数长度
    size_t raw_string_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &raw_string, &raw_string_len) == FAILURE) {
        RETURN_NULL();
    }
    easy_compiler_eval(raw_string,raw_string_len,return_value);
};

static void easy_compiler_eval(unsigned char *raw_string,size_t raw_string_len,zval *retval)
{
    zend_string *eval_string;
    zval z_str;
    eval_string = zend_string_init(raw_string,raw_string_len,0);
    ZVAL_STR(&z_str,eval_string);
    zend_op_array *new_op_array;
    char *filename = zend_get_executed_filename();
    new_op_array = easy_compiler_compile_string(&z_str, filename);
    if(new_op_array){
        zend_try {
            zend_execute(new_op_array,retval);
        } zend_catch {

        } zend_end_try();
        destroy_op_array(new_op_array);
        efree(new_op_array);
    }
}


//opcode处理
static void easy_compiler_mix_op_code(zend_op_array* opline) {
  if (NULL != opline) {
    size_t i;
    for (i = 0; i < opline->last; i++) {
      zend_op* orig_opline = &(opline->opcodes[i]);
      if (orig_opline->opcode == ZEND_IS_EQUAL) {
        orig_opline->opcode = ZEND_IS_IDENTICAL;
        zend_vm_set_opcode_handler(orig_opline);
      } else if (orig_opline->opcode == ZEND_IS_NOT_EQUAL) {
        orig_opline->opcode = ZEND_IS_NOT_IDENTICAL;
        zend_vm_set_opcode_handler(orig_opline);
      }
    }
  }
}


static zend_op_array *easy_compiler_compile_string(zval *source_string, char *filename)
{
    zend_op_array* opline = compile_string(source_string, filename);
    easy_compiler_mix_op_code(opline);
    return opline;
    //以下为eval等混淆破解
//    if (Z_TYPE_P(source_string) != IS_STRING)
//    {
//        return orig_compile_string(source_string, filename);
//    }
//    int len;
//    char *str;
//    len  = Z_STRLEN_P(source_string);
//    str = estrndup(Z_STRVAL_P(source_string), len);
//    printf("\n==========DUMP===========\n");
//    printf("%s", str);
//    printf("\n==========DUMP===========\n");
//    return orig_compile_string(source_string, filename);
}

static zend_op_array *easy_compiler_compile_file(zend_file_handle *file_handle, int type)
{
    zend_op_array* opline = compile_file(file_handle, type);
    easy_compiler_mix_op_code(opline);
    return opline;
     //以下为eval等混淆破解
//    char *buf;
//    size_t size;
//    if(zend_stream_fixup(file_handle,&buf,&size)==SUCCESS)
//    {
//        printf("%s",file_handle->filename);
//        printf("\n==========DUMP===========\n");
//        int i = 0;
//        for(i=0;i<=size;i++)
//        {
//            printf("%c",buf[i]);
//        }
//        printf("\n==========DUMP===========\n");
//    }
//    return compile_file(file_handle,type);
}
